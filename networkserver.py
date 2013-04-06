# Eloipool - Python Bitcoin pool server
# Copyright (C) 2011-2013  Luke Dashjr <luke-jr+eloipool@utopios.org>
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
import threading
from time import time
import traceback
from util import ScheduleDict, WithNoop, tryErr

EPOLL_READ = select.EPOLLIN | select.EPOLLPRI | select.EPOLLERR | select.EPOLLHUP
EPOLL_WRITE = select.EPOLLOUT

class SocketHandler:
	ac_in_buffer_size = 4096
	ac_out_buffer_size = 4096
	
	def handle_close(self):
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
		
		self.server.lastReadbuf = self.ac_in_buffer
		
		self.handle_readbuf()
	
	collect_incoming_data = asynchat.async_chat._collect_incoming_data
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
	
	def push(self, data):
		if not len(self.wbuf):
			# Try to send as much as we can immediately
			try:
				bs = self.socket.send(data)
			except:
				# Chances are we'll fail later, but anyway...
				bs = 0
			data = data[bs:]
			if not len(data):
				return
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
		if self.fd == -1:
			# Already closed
			return
		try:
			del self.server.connections[id(self)]
		except:
			pass
		self.server.unregister_socket(self.fd)
		self.changeTask(None)
		self.socket.close()
		self.fd = -1
	
	def boot(self):
		self.close()
		self.ac_in_buffer = b''
	
	def changeTask(self, f, t = None):
		tryErr(self.server.rmSchedule, self._Task, IgnoredExceptions=KeyError)
		if f:
			self._Task = self.server.schedule(f, t, errHandler=self)
		else:
			self._Task = None
	
	def __init__(self, server, sock, addr):
		self.ac_in_buffer = b''
		self.incoming = []
		self.wbuf = b''
		self.closeme = False
		self.server = server
		self.socket = sock
		self.addr = addr
		self._Task = None
		self.fd = sock.fileno()
		server.register_socket(self.fd, self)
		server.connections[id(self)] = self
		self.changeTask(self.handle_timeout, time() + 15)
	
	@classmethod
	def _register(cls, scls):
		for a in dir(scls):
			if a == 'final_init':
				f = lambda self, x=getattr(cls, a), y=getattr(scls, a): (x(self), y(self))
				setattr(cls, a, f)
				continue
			if a[0] == '_':
				continue
			setattr(cls, a, getattr(scls, a))

class NetworkListener:
	logger = logging.getLogger('SocketListener')
	
	def __init__(self, server, server_address, address_family = socket.AF_INET6):
		self.server = server
		self.server_address = server_address
		self.address_family = address_family
		tryErr(self.setup_socket, server_address, Logger=self.logger, ErrorMsg=server_address)
	
	def _makebind_py(self, server_address):
		sock = socket.socket(self.address_family, socket.SOCK_STREAM)
		sock.setblocking(0)
		try:
			sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		except socket.error:
			pass
		sock.bind(server_address)
		return sock
	
	def _makebind_su(self, server_address):
		if self.address_family != socket.AF_INET6:
			raise NotImplementedError
		
		from bindservice import bindservice
		(node, service) = server_address
		if not node: node = ''
		if not service: service = ''
		fd = bindservice(str(node), str(service))
		sock = socket.fromfd(fd, socket.AF_INET6, socket.SOCK_STREAM)
		sock.setblocking(0)
		return sock
	
	def _makebind(self, *a, **ka):
		try:
			return self._makebind_py(*a, **ka)
		except BaseException as e:
			try:
				return self._makebind_su(*a, **ka)
			except:
				pass
			raise
	
	def setup_socket(self, server_address):
		sock = self._makebind(server_address)
		sock.listen(100)
		self.server.register_socket(sock.fileno(), self)
		self.socket = sock
	
	def handle_read(self):
		server = self.server
		conn, addr = self.socket.accept()
		if server.rejecting:
			conn.close()
			return
		conn.setblocking(False)
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
	schMT = False
	
	def __init__(self, RequestHandlerClass):
		if not hasattr(self, 'ServerName'):
			self.ServerName = 'Eloipool'
		
		self.RequestHandlerClass = RequestHandlerClass
		
		self.running = False
		self.keepgoing = True
		self.rejecting = False
		self.lastidle = 0
		
		self._epoll = select.epoll()
		self._fd = {}
		self.connections = {}
		
		self._sch = ScheduleDict()
		self._schEH = {}
		if self.schMT:
			self._schLock = threading.Lock()
		else:
			self._schLock = WithNoop
		
		self.TrustedForwarders = ()
		
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
		with self._schLock:
			self._sch[task] = startTime
			if errHandler:
				self._schEH[id(task)] = errHandler
		return task
	
	def rmSchedule(self, task):
		with self._schLock:
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
	
	def final_init(self):
		pass
	
	def boot_all(self):
		conns = tuple(self.connections.values())
		for c in conns:
			tryErr(lambda: c.boot())
	
	def serve_forever(self):
		self.running = True
		self.final_init()
		while self.keepgoing:
			self.doing = 'pre-schedule'
			self.pre_schedule()
			self.doing = 'schedule'
			timeNow = time()
			if len(self._sch):
				while True:
					with self._schLock:
						if not len(self._sch):
							timeout = -1
							break
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
			else:
				timeout = -1
			if self.lastidle < timeNow - 1:
				timeout = 0
			elif timeout < 0 or timeout > 1:
				timeout = 1
			
			self.doing = 'poll'
			try:
				events = self._epoll.poll(timeout=timeout)
			except (IOError, select.error):
				continue
			except:
				self.logger.error(traceback.format_exc())
				continue
			self.doing = 'events'
			if not events:
				self.lastidle = time()
			for (fd, e) in events:
				o = self._fd[fd]
				self.lastHandler = o
				try:
					if e & EPOLL_READ:
						o.handle_read()
					if e & EPOLL_WRITE:
						o.handle_write()
				except socket.error:
					tryErr(o.handle_error)
				except:
					self.logger.error(traceback.format_exc())
					tryErr(o.handle_error)
		self.doing = None
		self.running = False
