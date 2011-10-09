from base64 import b64decode
from binascii import a2b_hex, b2a_hex
from datetime import datetime
from email.utils import formatdate
import json
import logging
import os
import select
import socket
import socketserver
import threading
from time import mktime, time, sleep
import traceback
from util import RejectedShare, swap32

# TODO: keepalive/close
_CheckForDupesHACK = {}
class JSONRPCHandler(socketserver.StreamRequestHandler):
	HTTPStatus = {
		200: 'OK',
		401: 'Unauthorized',
		404: 'Not Found',
		405: 'Method Not Allowed',
		500: 'Internal Server Error',
	}
	
	logger = logging.getLogger('JSONRPCHandler')
	
	def sendReply(self, status=200, body=b'', headers=None):
		wfile = self.wfile
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
		wfile.write(buf)
	
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
	
	def doAuthenticate(self):
		self.sendReply(401, headers={'WWW-Authenticate': 'Basic realm="Eligius"'})
	
	def doLongpoll(self):
		self.sendReply(200, body=None)
		wfile = self.wfile
		wfile.write(b"1\r\n{\r\n")
		waitTime = self.reqinfo.get('MinWait', 15)  # TODO: make default configurable
		waitTime += time()
		
		with self.server._LPLock:
			self.server._LPCount += 1
			self.logger.debug("New LP client; %d total" % (self.server._LPCount,))
		
		LPWait = self.server._LPWait
		EP = select.epoll(2)
		EP.register(LPWait, select.EPOLLIN)
		while True:
			ev = EP.poll(45)  # TODO: make keepalive configurable
			if len(ev):
				break
			# Keepalive via chunked transfer encoding
			wfile.write(b"1\r\n \r\n")
			wfile.flush()
		
		with self.server._LPCountL:
			self.server._LPCount -= 1
			self.logger.debug("LP client woken; %d remaining" % (self.server._LPCount,))
		self.server._LPSem.release()
		
		now = time()
		if now < waitTime:
			sleep(waitTime - now);
		
		rv = self.doJSON_getwork()
		rv = {'id': 1, 'error': None, 'result': rv}
		rv = json.dumps(rv)
		rv = rv.encode('utf8')
		rv = rv[1:]  # strip the '{' we already sent
		wfile.write(('%x' % len(rv)).encode('utf8') + b"\r\n" + rv + b"\r\n0\r\n\r\n")
	
	def doJSON(self, data):
		# TODO: handle JSON errors
		data = data.decode('utf8')
		data = json.loads(data)
		method = 'doJSON_' + str(data['method']).lower()
		if not hasattr(self, method):
			return self.doError('No such method')
		# TODO: handle errors as JSON-RPC
		self._JSONHeaders = {}
		rv = getattr(self, method)(*tuple(data['params']))
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
		# TODO: rv['midstate'] = 
		return rv
	
	def doJSON_submitwork(self, datax):
		data = swap32(a2b_hex(datax))[:80]
		share = {
			'data': data,
			'_origdata' : datax,
			'username': self.Username,
			'remoteHost': self.request.getpeername()[0],
		}
		try:
			self.server.receiveShare(share)
		except RejectedShare as rej:
			self._JSONHeaders['X-Reject-Reason'] = str(rej)
			return False
		return True
	
	def handle_i(self):
		# TODO: handle socket errors
		rfile = self.rfile
		data = rfile.readline().strip()
		data = data.split(b' ')
		if not data[0] in (b'GET', b'POST'):
			return self.sendReply(405)
		path = data[1]
		if not path in (b'/', b'/LP'):
			return self.sendReply(404)
		self.CL = None
		self.Username = None
		self.reqinfo = {}
		while True:
			data = rfile.readline().strip()
			if not data:
				break
			data = tuple(map(lambda a: a.strip(), data.split(b':', 1)))
			method = 'doHeader_' + data[0].decode('ascii').lower()
			if hasattr(self, method):
				getattr(self, method)(data[1])
		if not self.Username:
			return self.doAuthenticate()
		data = rfile.read(self.CL) if self.CL else None
		try:
			if path == b'/LP':
				return self.doLongpoll()
			return self.doJSON(data)
		except socket.error:
			raise
		except:
			self.logger.error(traceback.format_exc())
			return self.doError('uncaught error')
	
	def handle(self):
		try:
			while True:
				self.handle_i()
		except socket.error:
			pass
	
setattr(JSONRPCHandler, 'doHeader_content-length', JSONRPCHandler.doHeader_content_length);
setattr(JSONRPCHandler, 'doHeader_x-minimum-wait', JSONRPCHandler.doHeader_x_minimum_wait);

class JSONRPCServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
	allow_reuse_address = True
	daemon_threads = True
	
	def __init__(self, server_address, RequestHandlerClass=JSONRPCHandler, *a, **k):
		self.logger = logging.getLogger('JSONRPCServer')
		
		self._LPCount = 0
		self._LPCountL = threading.Lock()
		self._LPLock = threading.Lock()
		self._LPSem = threading.Semaphore(0)
		self._LPWaitTime = time() + 15
		self._LPILock = threading.Lock()
		self._LPI = False
		self._LPWLock = threading.Lock()
		self._setupLongpoll()
		
		super().__init__(server_address, RequestHandlerClass, *a, **k)
	
	def serve_forever(self, *a, **k):
		while True:
			try:
				super().serve_forever(*a, **k)
			except select.error:
				pass
	
	def _setupLongpoll(self):
		(r, w) = os.pipe()
		self._LPWait = r
		self._LPWaitW = w
	
	def wakeLongpoll(self):
		self.logger.debug("(LPILock)")
		with self._LPILock:
			if self._LPI:
				self.logger.info('Ignoring longpoll attempt while another is waiting')
				return
			self._LPI = True
		
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
			OC = self._LPCount
			if not OC:
				self.logger.info('Nobody to longpoll')
				return
			self.logger.debug("%d clients to wake up..." % (OC,))
			
			now = time()
			
			os.close(self._LPWaitW)
			while True:
				self.logger.debug("... checking")
				with self._LPCountL:
					self.logger.debug("... %d left" % (self._LPCount,))
					if not self._LPCount:
						break
				self._LPSem.acquire()
			os.close(self._LPWait)
			self.logger.debug("... setup new LP sockets")
			self._setupLongpoll()
			
			self._LPWaitTime = time()
			self.logger.info('Longpoll woke up %d clients in %.3g seconds' % (OC, self._LPWaitTime - now))
			self._LPWaitTime += 5  # TODO: make configurable: minimum time between longpolls
