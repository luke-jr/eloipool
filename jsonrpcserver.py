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
from binascii import a2b_hex, b2a_hex
from datetime import datetime
from email.utils import formatdate
import json
import logging
try:
	import midstate
	assert midstate.SHA256(b'This is just a test, ignore it. I am making it over 64-bytes long.')[:8] == (0x755f1a94, 0x999b270c, 0xf358c014, 0xfd39caeb, 0x0dcc9ebc, 0x4694cd1a, 0x8e95678e, 0x75fac450)
except:
	logging.getLogger('jsonrpcserver').warning('Error importing \'midstate\' module; work will not provide midstates')
	midstate = None
import networkserver
import os
import re
import socket
from struct import pack
import threading
from time import mktime, time, sleep
import traceback
from util import RejectedShare, swap32

class WithinLongpoll(BaseException):
	pass

# TODO: keepalive/close
_CheckForDupesHACK = {}
class JSONRPCHandler(networkserver.SocketHandler):
	HTTPStatus = {
		200: 'OK',
		401: 'Unauthorized',
		404: 'Not Found',
		405: 'Method Not Allowed',
		500: 'Internal Server Error',
	}
	
	LPHeaders = {
		'X-Long-Polling': None,
	}
	
	logger = logging.getLogger('JSONRPCHandler')
	
	def sendReply(self, status=200, body=b'', headers=None):
		buf = "HTTP/1.1 %d %s\r\n" % (status, self.HTTPStatus.get(status, 'Eligius'))
		headers = dict(headers) if headers else {}
		headers['Date'] = formatdate(timeval=mktime(datetime.now().timetuple()), localtime=False, usegmt=True)
		headers.setdefault('Server', 'Eloipool')
		if body is None:
			headers.setdefault('Transfer-Encoding', 'chunked')
			body = b''
		else:
			headers['Content-Length'] = len(body)
		if status == 200:
			headers.setdefault('Content-Type', 'application/json')
			headers.setdefault('X-Long-Polling', '/LP')
			headers.setdefault('X-Roll-NTime', 'expire=120')
		elif body and body[0] == 123:  # b'{'
			headers.setdefault('Content-Type', 'application/json')
		for k, v in headers.items():
			if v is None: continue
			buf += "%s: %s\r\n" % (k, v)
		buf += "\r\n"
		buf = buf.encode('utf8')
		buf += body
		self.push(buf)
	
	def doError(self, reason = '', code = 100):
		reason = json.dumps(reason)
		reason = r'{"result":null,"id":null,"error":{"name":"JSONRPCError","code":%d,"message":%s}}' % (code, reason)
		return self.sendReply(500, reason.encode('utf8'))
	
	def doHeader_authorization(self, value):
		value = value.split(b' ')
		if len(value) != 2 or value[0] != b'Basic':
			return self.doError('Bad Authorization header')
		value = b64decode(value[1])
		value = value.split(b':')[0]
		self.Username = value.decode('utf8')
	
	def doHeader_content_length(self, value):
		self.CL = int(value)
	
	def doHeader_user_agent(self, value):
		self.reqinfo['UA'] = value
		quirks = self.quirks
		try:
			if value[:9] == b'phoenix/v':
				v = tuple(map(int, value[9:].split(b'.')))
				if v[0] < 2 and v[1] < 8 and v[2] < 1:
					quirks['NELH'] = None
		except:
			pass
		self.quirks = quirks
	
	def doHeader_x_minimum_wait(self, value):
		self.reqinfo['MinWait'] = int(value)
	
	def doHeader_x_mining_extensions(self, value):
		self.extensions = value.decode('ascii').lower().split(' ')
	
	def doAuthenticate(self):
		self.sendReply(401, headers={'WWW-Authenticate': 'Basic realm="Eligius"'})
	
	def doLongpoll(self):
		timeNow = time()
		
		self._LP = True
		if 'NELH' not in self.quirks:
			# [NOT No] Early Longpoll Headers
			self.sendReply(200, body=None, headers=self.LPHeaders)
			self.push(b"1\r\n{\r\n")
			self.changeTask(self._chunkedKA, timeNow + 45)
		else:
			self.changeTask(None)
		
		waitTime = self.reqinfo.get('MinWait', 15)  # TODO: make default configurable
		self.waitTime = waitTime + timeNow
		
		totfromme = self.LPTrack()
		self.server._LPClients[id(self)] = self
		self.logger.debug("New LP client; %d total; %d from %s" % (len(self.server._LPClients), totfromme, self.addr[0]))
		
		raise WithinLongpoll
	
	def _chunkedKA(self):
		# Keepalive via chunked transfer encoding
		self.push(b"1\r\n \r\n")
		self.changeTask(self._chunkedKA, time() + 45)
	
	def LPTrack(self):
		myip = self.addr[0]
		if myip not in self.server.LPTracking:
			self.server.LPTracking[myip] = 0
		self.server.LPTracking[myip] += 1
		return self.server.LPTracking[myip]
	
	def LPUntrack(self):
		self.server.LPTracking[self.addr[0]] -= 1
	
	def cleanupLP(self):
		# Called when the connection is closed
		if not self._LP:
			return
		self.changeTask(None)
		try:
			del self.server._LPClients[id(self)]
		except KeyError:
			pass
		self.LPUntrack()
	
	def wakeLongpoll(self):
		now = time()
		if now < self.waitTime:
			self.changeTask(self.wakeLongpoll, self.waitTime)
			return
		else:
			self.changeTask(None)
		
		self.LPUntrack()
		
		rv = self.doJSON_getwork()
		rv['submitold'] = True
		rv = {'id': 1, 'error': None, 'result': rv}
		rv = json.dumps(rv)
		rv = rv.encode('utf8')
		if 'NELH' not in self.quirks:
			rv = rv[1:]  # strip the '{' we already sent
			self.push(('%x' % len(rv)).encode('utf8') + b"\r\n" + rv + b"\r\n0\r\n\r\n")
		else:
			self.sendReply(200, body=rv, headers=self.LPHeaders)
		
		self.reset_request()
	
	def doJSON(self, data):
		# TODO: handle JSON errors
		data = data.decode('utf8')
		try:
			data = json.loads(data)
			method = 'doJSON_' + str(data['method']).lower()
		except ValueError:
			return self.doError(r'Parse error')
		except TypeError:
			return self.doError(r'Bad call')
		if not hasattr(self, method):
			return self.doError(r'Procedure not found')
		# TODO: handle errors as JSON-RPC
		self._JSONHeaders = {}
		params = data.setdefault('params', ())
		try:
			rv = getattr(self, method)(*tuple(data['params']))
		except Exception as e:
			self.logger.error(("Error during JSON-RPC call: %s%s\n" % (method, params)) + traceback.format_exc())
			return self.doError(r'Service error: %s' % (e,))
		if rv is None:
			# response was already sent (eg, authentication request)
			return
		rv = {'id': data['id'], 'error': None, 'result': rv}
		try:
			rv = json.dumps(rv)
		except:
			return self.doError(r'Error encoding reply in JSON')
		rv = rv.encode('utf8')
		return self.sendReply(200, rv, headers=self._JSONHeaders)
	
	getwork_rv_template = {
		'data': '000000800000000000000000000000000000000000000000000000000000000000000000000000000000000080020000',
		'target': 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffff00000000',
		'hash1': '00000000000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000010000',
	}
	def doJSON_getwork(self, data=None):
		if not data is None:
			return self.doJSON_submitwork(data)
		rv = dict(self.getwork_rv_template)
		hdr = self.server.getBlockHeader(self.Username)
		
		# FIXME: this assumption breaks with internal rollntime
		# NOTE: noncerange needs to set nonce to start value at least
		global _CheckForDupesHACK
		uhdr = hdr[:68] + hdr[72:]
		if uhdr in _CheckForDupesHACK:
			raise self.server.RaiseRedFlags(RuntimeError('issuing duplicate work'))
		_CheckForDupesHACK[uhdr] = None
		
		data = b2a_hex(swap32(hdr)).decode('utf8') + rv['data']
		# TODO: endian shuffle etc
		rv['data'] = data
		if midstate and 'midstate' not in self.extensions:
			h = midstate.SHA256(hdr)[:8]
			rv['midstate'] = b2a_hex(pack('<LLLLLLLL', *h)).decode('ascii')
		return rv
	
	def doJSON_submitwork(self, datax):
		data = swap32(a2b_hex(datax))[:80]
		share = {
			'data': data,
			'_origdata' : datax,
			'username': self.Username,
			'remoteHost': self.addr[0],
		}
		try:
			self.server.receiveShare(share)
		except RejectedShare as rej:
			self._JSONHeaders['X-Reject-Reason'] = str(rej)
			return False
		return True
	
	def doJSON_setworkaux(self, k, hexv = None):
		if self.Username != self.server.SecretUser:
			self.doAuthenticate()
			return None
		if hexv:
			self.server.aux[k] = a2b_hex(hexv)
		else:
			del self.server.aux[k]
		return True
	
	def handle_close(self):
		self.cleanupLP()
		self.changeTask(None)
		self.wbuf = None
		self.close()
	
	def handle_request(self):
		if not self.Username:
			return self.doAuthenticate()
		if not self.method in (b'GET', b'POST'):
			return self.sendReply(405)
		if not self.path in (b'/', b'/LP', b'/LP/'):
			return self.sendReply(404)
		try:
			if self.path[:3] == b'/LP':
				return self.doLongpoll()
			data = b''.join(self.incoming)
			return self.doJSON(data)
		except socket.error:
			raise
		except WithinLongpoll:
			raise
		except:
			self.logger.error(traceback.format_exc())
			return self.doError('uncaught error')
	
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
		self.quirks = {}
		while True:
			try:
				data = hs.pop(0)
			except IndexError:
				break
			data = tuple(map(lambda a: a.strip(), data.split(b':', 1)))
			method = 'doHeader_' + data[0].decode('ascii').lower()
			if hasattr(self, method):
				getattr(self, method)(data[1])
	
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
			self.reset_request()
		except WithinLongpoll:
			pass
	
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
	
	def reset_request(self):
		self.incoming = []
		self.set_terminator( (b"\n\n", b"\r\n\r\n") )
		self.reading_headers = True
		self._LP = False
		self.changeTask(self.handle_timeout, time() + 15)
	
	def collect_incoming_data(self, data):
		asynchat.async_chat._collect_incoming_data(self, data)
	
	def __init__(self, *a, **ka):
		super().__init__(*a, **ka)
		self.reset_request()
	
setattr(JSONRPCHandler, 'doHeader_content-length', JSONRPCHandler.doHeader_content_length);
setattr(JSONRPCHandler, 'doHeader_user-agent', JSONRPCHandler.doHeader_user_agent);
setattr(JSONRPCHandler, 'doHeader_x-minimum-wait', JSONRPCHandler.doHeader_x_minimum_wait);
setattr(JSONRPCHandler, 'doHeader_x-mining-extensions', JSONRPCHandler.doHeader_x_mining_extensions);

JSONRPCListener = networkserver.NetworkListener

class JSONRPCServer(networkserver.AsyncSocketServer):
	logger = logging.getLogger('JSONRPCServer')
	
	waker = True
	
	def __init__(self, *a, **ka):
		ka.setdefault('RequestHandlerClass', JSONRPCHandler)
		super().__init__(*a, **ka)
		
		self.SecretUser = None
		
		self.LPRequest = False
		self._LPClients = {}
		self._LPWaitTime = time() + 15
		
		self.LPTracking = {}
	
	def pre_schedule(self):
		if self.LPRequest == 1:
			self._LPsch()
	
	def wakeLongpoll(self):
		if self.LPRequest:
			self.logger.info('Ignoring longpoll attempt while another is waiting')
			return
		self.LPRequest = 1
		self.wakeup()
	
	def _LPsch(self):
		now = time()
		if self._LPWaitTime > now:
			delay = self._LPWaitTime - now
			self.logger.info('Waiting %.3g seconds to longpoll' % (delay,))
			self.schedule(self._actualLP, self._LPWaitTime)
			self.LPRequest = 2
		else:
			self._actualLP()
	
	def _actualLP(self):
		self.LPRequest = False
		C = tuple(self._LPClients.values())
		self._LPClients = {}
		if not C:
			self.logger.info('Nobody to longpoll')
			return
		OC = len(C)
		self.logger.debug("%d clients to wake up..." % (OC,))
		
		now = time()
		
		for ic in C:
			ic.wakeLongpoll()
		
		self._LPWaitTime = time()
		self.logger.info('Longpoll woke up %d clients in %.3f seconds' % (OC, self._LPWaitTime - now))
		self._LPWaitTime += 5  # TODO: make configurable: minimum time between longpolls
	
	def TopLPers(self, n = 0x10):
		tmp = list(self.LPTracking.keys())
		tmp.sort(key=lambda k: self.LPTracking[k])
		for jerk in map(lambda k: (k, self.LPTracking[k]), tmp[-n:]):
			print(jerk)
