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

from .varlen import varlenEncode
import asynchat
from binascii import b2a_hex
from collections import deque
import logging
import networkserver
import re
import socket
from struct import pack, unpack
from time import time
from util import dblsha, tryErr

MAX_PACKET_PAYLOAD = 0x200000

def makeNetAddr(addr):
	timestamp = pack('<L', int(time()))
	aIP = pack('>BBBB', *map(int, addr[0].split('.')))
	aPort = pack('>H', addr[1])
	return timestamp + b'\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xff\xff' + aIP + aPort

class BitcoinLink(networkserver.SocketHandler):
	logger = logging.getLogger('BitcoinLink')
	
	def __init__(self, *a, **ka):
		dest = ka.pop('dest', None)
		if dest:
			# Initiate outbound connection
			try:
				if ':' not in dest[0]:
					dest = ('::ffff:' + dest[0],) + tuple(x for x in dest[1:])
			except:
				pass
			sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
			sock.connect(dest)
			ka['sock'] = sock
			ka['addr'] = dest
		super().__init__(*a, **ka)
		self.dest = dest
		self.sentVersion = False
		self.changeTask(None)  # FIXME: TEMPORARY
		if dest:
			self.pushVersion()
	
	def handle_readbuf(self):
		netid = self.server.netid
		while self.ac_in_buffer:
			if self.ac_in_buffer[:4] != netid:
				p = self.ac_in_buffer.find(netid)
				if p == -1:
					p = asynchat.find_prefix_at_end(self.ac_in_buffer, netid)
					if p:
						self.ac_in_buffer = self.ac_in_buffer[-p:]
					else:
						self.ac_in_buffer = b''
					break
				self.ac_in_buffer = self.ac_in_buffer[p:]
			
			cmd = self.ac_in_buffer[4:0x10].rstrip(b'\0').decode('utf8')
			payloadLen = unpack('<L', self.ac_in_buffer[0x10:0x14])[0]
			if payloadLen > MAX_PACKET_PAYLOAD:
				raise RuntimeError('Packet payload is too long (%d bytes)' % (payloadLen,))
			payloadEnd = payloadLen + 0x18
			if len(self.ac_in_buffer) < payloadEnd:
				# Don't have the whole packet yet
				break
			
			method = 'doCmd_' + cmd
			cksum = self.ac_in_buffer[0x14:0x18]
			payload = self.ac_in_buffer[0x18:payloadEnd]
			self.ac_in_buffer = self.ac_in_buffer[payloadEnd:]
			
			realcksum = dblsha(payload)[:4]
			if realcksum != cksum:
				self.logger.debug('Wrong checksum on `%s\' message (%s vs actual:%s); ignoring' % (cmd, b2a_hex(cksum), b2a_hex(realcksum)))
				return
			
			if hasattr(self, method):
				getattr(self, method)(payload)
	
	def pushMessage(self, *a, **ka):
		self.push(self.server.makeMessage(*a, **ka))
	
	def makeVersion(self):
		r = pack('<lQq26s26sQ',
			60000,              # version
			0,                  # services bitfield
			int(time()),        # timestamp
			b'',                # FIXME: other-side address
			b'',                # FIXME: my-side address
			self.server.nonce,  # nonce
		)
		UA = self.server.userAgent
		r += varlenEncode(len(UA)) + UA
		r += b'\0\0\0\0'         # start_height
		return r
	
	def pushVersion(self):
		if self.sentVersion:
			return
		self.pushMessage('version', self.makeVersion())
		self.sentVersion = True
	
	def doCmd_version(self, payload):
		# FIXME: check for loopbacks
		self.pushVersion()
		# FIXME: don't send verack to ancient clients
		self.pushMessage('verack')

class BitcoinNode(networkserver.AsyncSocketServer):
	logger = logging.getLogger('BitcoinNode')
	
	waker = True
	
	def __init__(self, netid, *a, **ka):
		ka.setdefault('RequestHandlerClass', BitcoinLink)
		super().__init__(*a, **ka)
		self.netid = netid
		self.userAgent = b'/BitcoinNode:0.1/'
		self.nonce = 0  # FIXME
		self._om = deque()
	
	def pre_schedule(self):
		OM = self._om
		while OM:
			m = OM.popleft()
			CB = 0
			for c in self._fd.values():
				try:
					c.push(m)
				except:
					pass
				else:
					CB += 1
			cmd = m[4:0x10].rstrip(b'\0').decode('utf8')
			self.logger.info('Sent `%s\' to %d nodes' % (cmd, CB))
	
	def makeMessage(self, cmd, payload = b''):
		cmd = cmd.encode('utf8')
		assert len(cmd) <= 12
		cmd += b'\0' * (12 - len(cmd))
		
		cksum = dblsha(payload)[:4]
		payloadLen = pack('<L', len(payload))
		return self.netid + cmd + payloadLen + cksum + payload
	
	def submitBlock(self, payload):
		self._om.append(self.makeMessage('block', payload))
		self.wakeup()
