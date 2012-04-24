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

import asynchat
from base64 import b64decode
from datetime import datetime
from email.utils import formatdate
import logging
import networkserver
import os
import re
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
	
	def handle_error(self):
		self.logger.debug(traceback.format_exc())
		self.handle_close()
	
	get_terminator = asynchat.async_chat.get_terminator
	set_terminator = asynchat.async_chat.set_terminator
	
	def handle_readbuf(self):
		while self.ac_in_buffer:
			lb = len(self.ac_in_buffer)
			terminator = self.get_terminator()
			if not terminator:
				# no terminator, collect it all
				self.collect_incoming_data (self.ac_in_buffer)
				self.ac_in_buffer = b''
			elif isinstance(terminator, int):
				# numeric terminator
				n = terminator
				if lb < n:
					self.collect_incoming_data (self.ac_in_buffer)
					self.ac_in_buffer = b''
					self.terminator = self.terminator - lb
				else:
					self.collect_incoming_data (self.ac_in_buffer[:n])
					self.ac_in_buffer = self.ac_in_buffer[n:]
					self.terminator = 0
					self.found_terminator()
			else:
				# 3 cases:
				# 1) end of buffer matches terminator exactly:
				#    collect data, transition
				# 2) end of buffer matches some prefix:
				#    collect data to the prefix
				# 3) end of buffer does not match any prefix:
				#    collect data
				# NOTE: this supports multiple different terminators, but
				#       NOT ones that are prefixes of others...
				if isinstance(self.ac_in_buffer, type(terminator)):
					terminator = (terminator,)
				termidx = tuple(map(self.ac_in_buffer.find, terminator))
				try:
					index = min(x for x in termidx if x >= 0)
				except ValueError:
					index = -1
				if index != -1:
					# we found the terminator
					if index > 0:
						# don't bother reporting the empty string (source of subtle bugs)
						self.collect_incoming_data (self.ac_in_buffer[:index])
					specific_terminator = terminator[termidx.index(index)]
					terminator_len = len(specific_terminator)
					self.ac_in_buffer = self.ac_in_buffer[index+terminator_len:]
					# This does the Right Thing if the terminator is changed here.
					self.found_terminator()
				else:
					# check for a prefix of the terminator
					termidx = tuple(map(lambda a: asynchat.find_prefix_at_end (self.ac_in_buffer, a), terminator))
					index = max(termidx)
					if index:
						if index != lb:
							# we found a prefix, collect up to the prefix
							self.collect_incoming_data (self.ac_in_buffer[:-index])
							self.ac_in_buffer = self.ac_in_buffer[-index:]
						break
					else:
						# no prefix, collect it all
						self.collect_incoming_data (self.ac_in_buffer)
						self.ac_in_buffer = b''
	
	def handle_src_request(self):
		if _SourceFiles is None:
			return self.sendReply(404)
		# For AGPL compliance, allow direct downloads of source code
		p = self.path[5:]
		if p == b'':
			# List of files
			body = b'<html><head><title>Source Code</title></head><body>\t\n'
			for f in _SourceFiles:
				body += b'\t<a href="' + f + b'">\n' + f + b'\n\t</a><br>\n'
			body += b'\t</body></html>\n'
			return self.sendReply(body=body, headers={'Content-Type':'text/html'})
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
	
	collect_incoming_data = asynchat.async_chat._collect_incoming_data
	
	def __init__(self, *a, **ka):
		super().__init__(*a, **ka)
		self.quirks = dict(self.default_quirks)
		self.reset_request()
	
setattr(HTTPHandler, 'doHeader_content-length', HTTPHandler.doHeader_content_length);
setattr(HTTPHandler, 'doHeader_x-forwarded-for', HTTPHandler.doHeader_x_forwarded_for);
