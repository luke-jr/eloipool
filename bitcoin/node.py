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

# WARNING: This is broken. It works fine on testnet, but randomly loses its connection to mainnet bitcoind and doesn't recover. This means it can LOSE REAL BLOCKS. Usually the disconnect doesn't happen until you try to submit one, either, so it's like a thief in the night. :(
# I recommend using JSON-RPC getmemorypool to submit blocks instead.

from .varlen import varlenEncode
from collections import deque
import logging
import os
import select
import socket
from struct import pack, unpack
import threading
from time import sleep, time
import traceback
from util import dblsha, tryErr

EPOLL_READ = select.EPOLLIN | select.EPOLLPRI | select.EPOLLERR | select.EPOLLHUP
EPOLL_WRITE = select.EPOLLOUT

MAGIC_CONNECT = b'We are now connected! Yay! :)'
MAGIC_CONFIRM = b'I have received your data, ty'

class BitcoinLink:
	logger = logging.getLogger('BitcoinLink')
	
	def __init__(self, dest, netid):
		self.netid = netid
		self.dest = dest
		self._mq = deque()
		self._pm = []
		(r, w) = os.pipe()
		self._ping = w
		self._pingR = r
		thr = threading.Thread(target=self._threadFunc)
		thr.daemon = True
		thr.start()
	
	def _threadFunc(self):
		logger = self.logger
		pm = self._pm
		
		epoll = select.epoll()
		self._epoll = epoll
		epoll.register(self._pingR, EPOLL_READ)
		
		sck = None
		fd = None
		
		while True:
			try:
				sck.close()
				epoll.unregister(fd)
			except:
				pass
			
			try:
				sck = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				fd = sck.fileno()
				sck.connect(self.dest)
				self.sock = sck
				epoll.register(fd, EPOLL_READ | EPOLL_WRITE)
			except:
				emsg = "Failed to connect to bitcoin node"
				asap = len(self._mq)
				if asap:
					emsg += " with pending messages"
				emsg += "\n"
				emsg += traceback.format_exc()
				logger.critical(emsg)
				sleep(0.5 if asap else 5)
				continue
			
			try:
				self._mainloop()
				logger.debug("Bitcoin node got disconnected")
			except:
				logger.debug("Error in bitcoin node main loop:\n" + traceback.format_exc())
	
	def _mainloop(self):
		logger = self.logger
		epoll = self._epoll
		pm = self._pm
		sck = self.sock
		fd = sck.fileno()
		
		destAddr = self.makeNetAddr(sck.getpeername())
		payload = b'\0\0\1\0\0\0\0\0\0\0\0\0' + pack('<L', int(time())) + destAddr
		wbuf = self.makeMessage('version', payload)
		wbuf += self.makeMessage('checkorder', MAGIC_CONNECT)
		rbuf = b''
		for m in pm:
			wbuf += m
		pc = False
		
		while True:
			events = epoll.poll()
			for (efd, e) in events:
				if efd != fd:
					# wakeup pipe
					os.read(self._pingR, 1)
					continue
				# bitcoin p2p
				if e & EPOLL_READ:
					nrb = sck.recv(1024, socket.MSG_DONTWAIT)
					if not nrb:
						return
					idx = 0
					if MAGIC_CONFIRM in rbuf + nrb:
						# Confirmation of msg receipt ;)
						n = len(pm)
						pm[:] = ()
						pc = False
						idx = nrb.find(MAGIC_CONFIRM) + 1
						logger.debug("Confirmed %d bitcoin node messages received" % (n,))
					elif MAGIC_CONNECT in rbuf + nrb:
						idx = nrb.find(MAGIC_CONNECT) + 1
						logger.debug("Connected to bitcoin node")
					rbuf = nrb[idx:]
				if e & EPOLL_WRITE:
					n = sck.send(wbuf, socket.MSG_DONTWAIT)
					wbuf = wbuf[n:]
					if not wbuf:
						epoll.modify(fd, EPOLL_READ)
			if not pc:
				while len(self._mq):
					m = self._mq.popleft()
					pm.append(m)
					wbuf += m
				if pm:
					epoll.modify(fd, EPOLL_READ | EPOLL_WRITE)
					# FIXME: this only works if IP txns are disabled!
					wbuf += self.makeMessage('checkorder', MAGIC_CONFIRM)
					pc = True
					logger.debug("Attempting to send %d messages (%d bytes) to bitcoin node" % (len(pm), len(wbuf)))
	
	def makeMessage(self, cmd, payload, cksum = True):
		cmd = cmd.encode('utf8')
		assert len(cmd) <= 12
		cmd += b'\0' * (12 - len(cmd))
		payload += dblsha(payload)[:4] if cksum else b''
		payloadLen = pack('<L', len(payload))
		return self.netid + cmd + payloadLen + payload
	
	def sendMessage(self, *a, **k):
		m = self.makeMessage(*a, **k)
		self._mq.append(m)
		os.write(self._ping, b'\1')
	
	def makeNetAddr(self, addr):
		timestamp = pack('<L', int(time()))
		aIP = pack('>BBBB', *map(int, addr[0].split('.')))
		aPort = pack('>H', addr[1])
		return timestamp + b'\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xff\xff' + aIP + aPort
	
	def submitBlock(self, payload):
		self.sendMessage('block', payload)
