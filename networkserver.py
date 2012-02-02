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
import logging
import os
import select
import socket
from time import time
import traceback
from util import ScheduleDict, tryErr

EPOLL_READ = select.EPOLLIN | select.EPOLLPRI | select.EPOLLERR | select.EPOLLHUP
EPOLL_WRITE = select.EPOLLOUT

class SocketHandler:
	ac_in_buffer_size = 4096
	ac_out_buffer_size = 4096
	
	def handle_close(self):
		self.changeTask(None)
		self.wbuf = None
		self.close()
	
	def handle_error(self):
		self.logger.debug(traceback.format_exc())
		self.handle_close()
	
	def handle_read(self):
		try:
			data = self.recv (self.ac_in_buffer_size)
		except socket.error as why:
			self.handle_error()
			return
		
		if self.closeme:
			# All input is ignored from sockets we have "closed"
			return
		
		if isinstance(data, str) and self.use_encoding:
			data = bytes(str, self.encoding)
		self.ac_in_buffer = self.ac_in_buffer + data
		
		self.handle_readbuf()
	
	def push(self, data):
		self.wbuf += data
		self.server.register_socket_m(self.fd, EPOLL_READ | EPOLL_WRITE)
	
	def handle_timeout(self):
		self.close()
	
	def handle_write(self):
		if self.wbuf is None:
			# Socket was just closed by remote peer
			return
		bs = self.socket.send(self.wbuf)
		self.wbuf = self.wbuf[bs:]
		if not len(self.wbuf):
			if self.closeme:
				self.close()
				return
			self.server.register_socket_m(self.fd, EPOLL_READ)
	
	recv = asynchat.async_chat.recv
	
	def close(self):
		if self.wbuf:
			self.closeme = True
			return
		self.server.unregister_socket(self.fd)
		self.socket.close()
	
	def changeTask(self, f, t = None):
		tryErr(self.server.rmSchedule, self._Task, IgnoredExceptions=KeyError)
		if f:
			self._Task = self.server.schedule(f, t, errHandler=self)
	
	def __init__(self, server, sock, addr):
		self.ac_in_buffer = b''
		self.wbuf = b''
		self.closeme = False
		self.server = server
		self.socket = sock
		self.addr = addr
		self._Task = None
		self.fd = sock.fileno()
		server.register_socket(self.fd, self)
		self.changeTask(self.handle_timeout, time() + 15)

class NetworkListener:
	logger = logging.getLogger('SocketListener')
	
	def __init__(self, server, server_address, address_family = socket.AF_INET6):
		self.server = server
		self.server_address = server_address
		self.address_family = address_family
		tryErr(self.setup_socket, server_address, Logger=self.logger, ErrorMsg=server_address)
	
	def setup_socket(self, server_address):
		sock = socket.socket(self.address_family, socket.SOCK_STREAM)
		sock.setblocking(0)
		try:
			sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		except socket.error:
			pass
		sock.bind(server_address)
		sock.listen(100)
		self.server.register_socket(sock.fileno(), self)
		self.socket = sock
	
	def handle_read(self):
		server = self.server
		conn, addr = self.socket.accept()
		h = server.RequestHandlerClass(server, conn, addr)
	
	def handle_error(self):
		# Ignore errors... like socket closing on the queue
		pass

class _Waker:
	def __init__(self, server, fd):
		self.server = server
		self.fd = fd
		self.logger = logging.getLogger('Waker for %s' % (server.__class__.__name__,))
	
	def handle_read(self):
		data = os.read(self.fd, 1)
		if not data:
			self.logger.error('Got EOF on socket')
		self.logger.debug('Read wakeup')

class AsyncSocketServer:
	logger = logging.getLogger('SocketServer')
	
	waker = False
	
	def __init__(self, RequestHandlerClass):
		self.RequestHandlerClass = RequestHandlerClass
		
		self.running = False
		self.keepgoing = True
		
		self._epoll = select.epoll()
		self._fd = {}
		
		self._sch = ScheduleDict()
		self._schEH = {}
		
		if self.waker:
			(r, w) = os.pipe()
			o = _Waker(self, r)
			self.register_socket(r, o)
			self.waker = w
	
	def register_socket(self, fd, o, eventmask = EPOLL_READ):
		self._epoll.register(fd, eventmask)
		self._fd[fd] = o
	
	def register_socket_m(self, fd, eventmask):
		try:
			self._epoll.modify(fd, eventmask)
		except IOError:
			raise socket.error
	
	def unregister_socket(self, fd):
		del self._fd[fd]
		try:
			self._epoll.unregister(fd)
		except IOError:
			raise socket.error
	
	def schedule(self, task, startTime, errHandler=None):
		self._sch[task] = startTime
		if errHandler:
			self._schEH[id(task)] = errHandler
		return task
	
	def rmSchedule(self, task):
		del self._sch[task]
		k = id(task)
		if k in self._schEH:
			del self._schEH[k]
	
	def pre_schedule(self):
		pass
	
	def wakeup(self):
		if not self.waker:
			raise NotImplementedError('Class `%s\' did not enable waker' % (self.__class__.__name__))
		os.write(self.waker, b'\1')  # to break out of the epoll
	
	def serve_forever(self):
		self.running = True
		while self.keepgoing:
			self.pre_schedule()
			if len(self._sch):
				timeNow = time()
				while True:
					timeNext = self._sch.nextTime()
					if timeNow < timeNext:
						timeout = timeNext - timeNow
						break
					f = self._sch.shift()
					k = id(f)
					EH = None
					if k in self._schEH:
						EH = self._schEH[k]
						del self._schEH[k]
					try:
						f()
					except socket.error:
						if EH: tryErr(EH.handle_error)
					except:
						self.logger.error(traceback.format_exc())
						if EH: tryErr(EH.handle_close)
					if not len(self._sch):
						timeout = -1
						break
			else:
				timeout = -1
			
			try:
				events = self._epoll.poll(timeout=timeout)
			except (IOError, select.error):
				continue
			except:
				self.logger.error(traceback.format_exc())
			for (fd, e) in events:
				o = self._fd[fd]
				try:
					if e & EPOLL_READ:
						o.handle_read()
					if e & EPOLL_WRITE:
						o.handle_write()
				except socket.error:
					tryErr(o.handle_error)
				except:
					self.logger.error(traceback.format_exc())
					tryErr(o.handle_close)
		self.running = False
