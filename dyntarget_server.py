#!/usr/bin/python3
# Eloipool - Python Bitcoin pool server
# Copyright (C) 2013  Luke Dashjr <luke-jr+eloipool@utopios.org>
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

import dyntarget
import logging
import networkserver
import struct
import time

class DyntargetHandler(networkserver.SocketHandler):
	logger = logging.getLogger('DyntargetHandler')
	
	def __init__(self, *a, **ka):
		super().__init__(*a, **ka)
		self.push(b'Dyntarget Server 0\0')
		self.set_terminator(b'\0')
	
	def process_data(self, inbuf):
		# NOTE: Replaced after version negotiation
		assert inbuf[:17] == b'Dyntarget Client '
		self.changeTask(None)
		self.reset_process()
	
	def reset_process(self):
		self.process_data = self.process_hashes
		self.set_terminator(9)
	
	def process_hashes(self, inbuf):
		assert inbuf[0:1] == b'\0'
		(self.hashes,) = struct.unpack('!Q', inbuf[1:])
		
		self.process_data = self.process_username
		self.set_terminator(b'\0')
	
	def process_username(self, inbuf):
		username = inbuf
		self.server.workCompleted(self, username, self.hashes)
		
		self.reset_process()

class DyntargetServer(networkserver.AsyncSocketServer):
	logger = logging.getLogger('DyntargetServer')
	
	def __init__(self, *a, **ka):
		ka.setdefault('RequestHandlerClass', DyntargetHandler)
		super().__init__(*a, **ka)
	
	def workCompleted(self, handler, username, hashes):
		self.manager.workCompleted(username, hashes)
		now = time.time()
		self.sendTarget(username, now)
	
	def sendTarget(self, username, now):
		tgt = self.manager.getTarget(username, now) or self.manager.ShareTarget
		pkt = b''
		for i in range(4):
			pkt = struct.pack('!Q', tgt & 0xffffffffffffffff) + pkt
			tgt >>= 64
		pkt = b'\1' + (pkt * 2) + username + b'\0'
		for c in self.connections.values():
			c.push(pkt)

if __name__ == '__main__':
	import config
	
	logging.basicConfig(
		format='%(asctime)s\t%(name)s\t%(levelname)s\t%(message)s',
		level=logging.DEBUG,
	)
	
	srv = DyntargetServer()
	
	mgr = dyntarget.DyntargetManager()
	mgr.minTarget = 0
	mgr.__dict__.update(config.__dict__)
	srv.manager = mgr
	
	for a in config.DynamicTargetServerAddresses:
		networkserver.NetworkListener(srv, a)
	
	srv.allowint = True
	srv.serve_forever()
