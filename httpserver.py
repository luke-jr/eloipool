# Eloipool - Python Bitcoin pool server
# Copyright (C) 2011-2012  Luke Dashjr <luke-jr+eloipool@utopios.org>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from base64 import b64decode
from datetime import datetime
from email.utils import formatdate
from gzip import GzipFile
import io
import logging
import networkserver
import os
import re
import stat
from struct import pack
from time import mktime, time
import traceback

# It is not legal to bypass or lie to this check. See LICENSE file for details.
try:
	_srcdir = os.path.dirname(os.path.abspath(__file__))
	if os.path.exists(_srcdir + '/.I_swear_that_I_am_Luke_Dashjr'):
		_SourceFiles = None
	else:
		_SourceFiles = os.popen('cd \'%s\' && git ls-files' % (_srcdir,)).read().split('\n')
		try:
			_SourceFiles.remove('')
		except ValueError:
			pass
		if len(_SourceFiles) < 2:
			raise RuntimeError('Unknown error')
		_SourceFiles = tuple(x.encode('utf8') for x in _SourceFiles)
		_GitDesc = os.popen('cd \'%s\' && git describe --dirty --always' % (_srcdir,)).read().strip().encode('utf8')
except BaseException as e:
	logging.getLogger('Licensing').critical('Error getting list of source files! AGPL requires this. To fix, be sure you are using git for Eloipool.\n' + traceback.format_exc())
	import sys
	sys.exit(1)

class AsyncRequest(BaseException):
	pass

class RequestAlreadyHandled(BaseException):
	pass

class RequestHandled(RequestAlreadyHandled):
	pass

class RequestNotHandled(BaseException):
	pass

class HTTPHandler(networkserver.SocketHandler):
	HTTPStatus = {
		200: 'OK',
		401: 'Unauthorized',
		404: 'Not Found',
		405: 'Method Not Allowed',
		500: 'Internal Server Error',
	}
	
	logger = logging.getLogger('HTTPHandler')
	
	default_quirks = {}
	
	def sendReply(self, status=200, body=b'', headers=None):
		if self.replySent:
			raise RequestAlreadyHandled
		buf = "HTTP/1.1 %d %s\r\n" % (status, self.HTTPStatus.get(status, 'Unknown'))
		headers = dict(headers) if headers else {}
		headers['Date'] = formatdate(timeval=mktime(datetime.now().timetuple()), localtime=False, usegmt=True)
		headers.setdefault('Server', 'Eloipool')
		if not _SourceFiles is None:
			headers.setdefault('X-Source-Code', '/src/')
		if body is None:
			headers.setdefault('Transfer-Encoding', 'chunked')
		else:
			if 'gzip' in self.quirks:
				headers['Content-Encoding'] = 'gzip'
				headers['Vary'] = 'Content-Encoding'
				gz = io.BytesIO()
				with GzipFile(fileobj=gz, mode='wb') as raw:
					raw.write(body)
				body = gz.getvalue()
			headers['Content-Length'] = len(body)
		for k, v in headers.items():
			if v is None: continue
			buf += "%s: %s\r\n" % (k, v)
		buf += "\r\n"
		buf = buf.encode('utf8')
		self.replySent = True
		if body is None:
			self.push(buf)
			return
		buf += body
		self.push(buf)
		raise RequestHandled
	
	def doError(self, reason = '', code = 100, headers = None):
		if headers is None: headers = {}
		headers.setdefault('Content-Type', 'text/plain')
		return self.sendReply(500, reason.encode('utf8'), headers)
	
	def doHeader_accept_encoding(self, value):
		if b'gzip' in value:
			self.quirks['gzip'] = True
	
	def doHeader_authorization(self, value):
		value = value.split(b' ')
		if len(value) != 2 or value[0] != b'Basic':
			return self.doError('Bad Authorization header')
		value = b64decode(value[1])
		(un, pw, *x) = value.split(b':', 1) + [None]
		valid = False
		try:
			valid = self.checkAuthentication(un, pw)
		except:
			return self.doError('Error checking authorization')
		if valid:
			self.Username = un.decode('utf8')
	
	def doHeader_connection(self, value):
		if value == b'close':
			self.quirks['close'] = None
	
	def doHeader_content_length(self, value):
		self.CL = int(value)
	
	def doHeader_x_forwarded_for(self, value):
		if self.addr[0] in self.server.TrustedForwarders:
			self.remoteHost = value.decode('ascii')
		else:
			self.logger.debug("Ignoring X-Forwarded-For header from %s" % (self.addr[0],))
	
	def doAuthenticate(self):
		self.sendReply(401, headers={'WWW-Authenticate': 'Basic realm="%s"' % (self.server.ServerName,)})
	
	def parse_headers(self, hs):
		self.CL = None
		self.Username = None
		self.method = None
		self.path = None
		hs = re.split(br'\r?\n', hs)
		data = hs.pop(0).split(b' ')
		try:
			self.method = data[0]
			self.path = data[1]
		except IndexError:
			self.close()
			return
		self.extensions = []
		self.reqinfo = {}
		self.quirks = dict(self.default_quirks)
		if data[2:] != [b'HTTP/1.1']:
			self.quirks['close'] = None
		while True:
			try:
				data = hs.pop(0)
			except IndexError:
				break
			data = tuple(map(lambda a: a.strip(), data.split(b':', 1)))
			method = 'doHeader_' + data[0].decode('ascii').lower()
			if hasattr(self, method):
				try:
					getattr(self, method)(data[1])
				except RequestAlreadyHandled:
					# Ignore multiple errors and such
					pass
	
	def found_terminator(self):
		if self.reading_headers:
			inbuf = b"".join(self.incoming)
			self.incoming = []
			m = re.match(br'^[\r\n]+', inbuf)
			if m:
				inbuf = inbuf[len(m.group(0)):]
			if not inbuf:
				return
			
			self.reading_headers = False
			self.parse_headers(inbuf)
			if self.CL:
				self.set_terminator(self.CL)
				return
		
		self.set_terminator(None)
		try:
			self.handle_request()
			raise RequestNotHandled
		except RequestHandled:
			self.reset_request()
		except AsyncRequest:
			pass
		except:
			self.logger.error(traceback.format_exc())
	
	def handle_src_request(self):
		if _SourceFiles is None:
			return self.sendReply(404)
		# For AGPL compliance, allow direct downloads of source code
		p = self.path[5:]
		if p == b'':
			# List of files
			body = b'<html><head><title>Source Code</title></head><body>\t\n'
			body += b'\t<a href="tar">(tar archive of all files)</a><br><br>\n'
			for f in _SourceFiles:
				body += b'\t<a href="' + f + b'">\n' + f + b'\n\t</a><br>\n'
			body += b'\t</body></html>\n'
			return self.sendReply(body=body, headers={'Content-Type':'text/html'})
		if p == b'tar':
			body = bytearray()
			dn = b'eloipool-' + _GitDesc + b'/'
			for f in _SourceFiles:
				fs = f.decode('utf8')
				fstat = os.lstat(fs)
				islink = stat.S_ISLNK(fstat.st_mode)
				if islink:
					data = b''
					link = os.readlink(f)
				else:
					with open("%s/%s" % (_srcdir, fs), 'rb') as ff:
						data = ff.read()
					link = b''
				h = bytearray()
				f = dn + f
				h += f + bytes(max(0, 100 - len(f)))
				h += ('%07o' % (fstat.st_mode,)[-7:]).encode('utf8') + b'\0'
				h += bytes(16)
				h += ('%012o%012o' % (fstat.st_size, fstat.st_mtime)).encode('utf8')
				h += b'        '  # chksum
				h += b'2' if islink else b'0'
				h += link + bytes(max(0, 355 - len(link)))
				h[148:156] = ('%07o' % (sum(h),)).encode('utf8') + b'\0'
				body += h + data + bytes(512 - ((fstat.st_size % 512) or 512))
			self.sendReply(body=body, headers={'Content-Type':'application/x-tar'})
		if p not in _SourceFiles:
			return self.sendReply(404)
		ct = 'text/plain'
		if p[-3:] == b'.py': ct = 'application/x-python'
		elif p[-11:] == b'.py.example': ct = 'application/x-python'
		p = p.decode('utf8')
		with open("%s/%s" % (_srcdir, p), 'rb') as f:
			self.sendReply(body=f.read(), headers={'Content-Type':ct})
	
	def reset_request(self):
		self.replySent = False
		self.incoming = []
		self.set_terminator( (b"\n\n", b"\r\n\r\n") )
		self.reading_headers = True
		self.changeTask(self.handle_timeout, time() + 150)
		if 'close' in self.quirks:
			self.close()
		# proxies can do multiple requests in one connection for multiple clients, so reset address every time
		self.remoteHost = self.addr[0]
	
	def __init__(self, *a, **ka):
		super().__init__(*a, **ka)
		self.quirks = dict(self.default_quirks)
		self.reset_request()
	
setattr(HTTPHandler, 'doHeader_accept-encoding', HTTPHandler.doHeader_accept_encoding);
setattr(HTTPHandler, 'doHeader_content-length', HTTPHandler.doHeader_content_length);
setattr(HTTPHandler, 'doHeader_x-forwarded-for', HTTPHandler.doHeader_x_forwarded_for);
