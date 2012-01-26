import asynchat
import asyncore
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
	midstate = None
import os
import re
import select
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
class JSONRPCHandler(asynchat.async_chat):
	HTTPStatus = {
		200: 'OK',
		401: 'Unauthorized',
		404: 'Not Found',
		405: 'Method Not Allowed',
		500: 'Internal Server Error',
	}
	
	logger = logging.getLogger('JSONRPCHandler')
	
	def sendReply(self, status=200, body=b'', headers=None):
		buf = "HTTP/1.1 %d %s\r\n" % (status, self.HTTPStatus.get(status, 'Eligius'))
		headers = dict(headers) if headers else {}
		headers['Date'] = formatdate(timeval=mktime(datetime.now().timetuple()), localtime=False, usegmt=True)
		if body is None:
			headers.setdefault('Transfer-Encoding', 'chunked')
			body = b''
		else:
			headers['Content-Length'] = len(body)
		if status == 200:
			headers.setdefault('Content-Type', 'application/json')
			headers.setdefault('X-Long-Polling', '/LP')
			headers.setdefault('X-Roll-NTime', 'expire=120')
		for k, v in headers.items():
			if v is None: continue
			buf += "%s: %s\r\n" % (k, v)
		buf += "\r\n"
		buf = buf.encode('utf8')
		buf += body
		self.push(buf)
	
	def doError(self, reason = ''):
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
	
	def doHeader_x_minimum_wait(self, value):
		self.reqinfo['MinWait'] = int(value)
	
	def doHeader_x_mining_extensions(self, value):
		self.extensions = value.decode('ascii').lower().split(' ')
	
	def doAuthenticate(self):
		self.sendReply(401, headers={'WWW-Authenticate': 'Basic realm="Eligius"'})
	
	def doLongpoll(self):
		self.sendReply(200, body=None)
		self.push(b"1\r\n{\r\n")
		waitTime = self.reqinfo.get('MinWait', 15)  # TODO: make default configurable
		timeNow = time()
		self.waitTime = waitTime + timeNow
		
		with self.server._LPLock:
			self.server._LPClients[id(self)] = self
			self.server.schedule(self._chunkedKA, timeNow + 45)
			self.logger.debug("New LP client; %d total" % (len(self.server._LPClients),))
		
		raise WithinLongpoll
	
	def _chunkedKA(self):
		# Keepalive via chunked transfer encoding
		self.push(b"1\r\n \r\n")
		self.server.schedule(self._chunkedKA, time() + 45)
	
	def cleanupLP(self):
		# Called when the connection is closed
		with self.server._LPLock:
			try:
				del self.server._LPClients[id(self)]
			except KeyError:
				pass
		self.server.rmSchedule(self._chunkedKA, self.wakeLongpoll)
	
	def wakeLongpoll(self):
		self.cleanupLP()
		
		now = time()
		if now < self.waitTime:
			self.server.schedule(self.wakeLongpoll, self.waitTime)
			return
		
		self.server.rmSchedule(self._chunkedKA)
		
		rv = self.doJSON_getwork()
		rv = {'id': 1, 'error': None, 'result': rv}
		rv = json.dumps(rv)
		rv = rv.encode('utf8')
		rv = rv[1:]  # strip the '{' we already sent
		self.push(('%x' % len(rv)).encode('utf8') + b"\r\n" + rv + b"\r\n0\r\n\r\n")
		
		self.reset_request()
	
	def doJSON(self, data):
		# TODO: handle JSON errors
		data = data.decode('utf8')
		data = json.loads(data)
		method = 'doJSON_' + str(data['method']).lower()
		if not hasattr(self, method):
			return self.doError('No such method')
		# TODO: handle errors as JSON-RPC
		self._JSONHeaders = {}
		rv = getattr(self, method)(*tuple(data.get('params', ())))
		if rv is None:
			return
		rv = {'id': data['id'], 'error': None, 'result': rv}
		rv = json.dumps(rv)
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
			'remoteHost': self.addr,
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
		hs = re.split(br'\r?\n', hs)
		data = hs.pop(0).split(b' ')
		self.method = data[0]
		self.path = data[1]
		self.CL = None
		self.extensions = []
		self.Username = None
		self.reqinfo = {}
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
			self.reading_headers = False
			self.parse_headers(b"".join(self.incoming))
			self.incoming = []
			if self.CL:
				self.set_terminator(self.CL)
				return
		
		self.set_terminator(None)
		try:
			self.handle_request()
			self.reset_request()
		except WithinLongpoll:
			pass
	
	def handle_read (self):
		try:
			data = self.recv (self.ac_in_buffer_size)
		except socket.error as why:
			self.handle_error()
			return
		
		if isinstance(data, str) and self.use_encoding:
			data = bytes(str, self.encoding)
		self.ac_in_buffer = self.ac_in_buffer + data
		
		# Continue to search for self.terminator in self.ac_in_buffer,
		# while calling self.collect_incoming_data.  The while loop
		# is necessary because we might read several data+terminator
		# combos with a single recv(4096).
		
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
					index = min(x for x in termidx if x >= 0)
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
	
	def collect_incoming_data(self, data):
		asynchat.async_chat._collect_incoming_data(self, data)
	
	def __init__(self, sock, addr, map):
		asynchat.async_chat.__init__(self, sock=sock, map=map)
		self.addr = addr
		self.reset_request()
	
setattr(JSONRPCHandler, 'doHeader_content-length', JSONRPCHandler.doHeader_content_length);
setattr(JSONRPCHandler, 'doHeader_x-minimum-wait', JSONRPCHandler.doHeader_x_minimum_wait);
setattr(JSONRPCHandler, 'doHeader_x-mining-extensions', JSONRPCHandler.doHeader_x_mining_extensions);

class JSONRPCServer(asyncore.dispatcher):
	def __init__(self, server_address, RequestHandlerClass=JSONRPCHandler, map={}):
		self.logger = logging.getLogger('JSONRPCServer')
		
		asyncore.dispatcher.__init__(self, map=map)
		self.map = map
		self.create_socket(socket.AF_INET6, socket.SOCK_STREAM)
		self.set_reuse_addr()
		self.bind(server_address)
		self.listen(100)
		#self.server_address = self.socket.getsockname()
		
		self.SecretUser = None
		
		self._schLock = threading.RLock()
		self._sch = []
		
		self._LPClients = {}
		self._LPLock = threading.RLock()
		self._LPWaitTime = time() + 15
		self._LPILock = threading.Lock()
		self._LPI = False
		self._LPWLock = threading.Lock()
	
	def handle_accept(self):
		conn, addr = self.accept()
		h = JSONRPCHandler(conn, addr, map=self.map)
		h.server = self
	
	def schedule(self, task, startTime):
		with self._schLock:
			IL = len(self._sch)
			while IL and startTime < self._sch[IL-1][0]:
				IL -= 1
			self._sch.insert(IL, (startTime, task))
	
	def rmSchedule(self, *tasks):
		tasks = list(tasks)
		with self._schLock:
			i = 0
			SL = len(self._sch)
			while i < SL:
				if self._sch[i][1] in tasks:
					tasks.remove(self._sch[i][1])
					del self._sch[i]
					if not tasks:
						break
					SL -= 1
				else:
					i += 1
	
	def serve_forever(self):
		while True:
			with self._schLock:
				if len(self._sch):
					timeNow = time()
					while True:
						timeNext = self._sch[0][0]
						if timeNow < timeNext:
							timeout = timeNext - timeNow
							break
						f = self._sch.pop(0)[1]
						f()
						if not len(self._sch):
							timeout = None
							break
				else:
					timeout = None
			try:
				asyncore.loop(use_poll=True, map=self.map, timeout=timeout, count=1)
			except select.error:
				pass
	
	def wakeLongpoll(self):
		self.logger.debug("(LPILock)")
		with self._LPILock:
			if self._LPI:
				self.logger.info('Ignoring longpoll attempt while another is waiting')
				return
			self._LPI = True
		
		th = threading.Thread(target=self._LPthread)
		th.daemon = True
		th.start()
	
	def _LPthread(self):
		self.logger.debug("(LPWLock)")
		with self._LPWLock:
			now = time()
			if self._LPWaitTime > now:
				delay = self._LPWaitTime - now
				self.logger.info('Waiting %.3g seconds to longpoll' % (delay,))
				sleep(delay)
			
			self._LPI = False
			
			self._actualLP()
	
	def _actualLP(self):
		self.logger.debug("(LPLock)")
		with self._LPLock:
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
