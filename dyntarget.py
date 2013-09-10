#!/usr/bin/python3
# Eloipool - Python Bitcoin pool server
# Copyright (C) 2012-2013  Luke Dashjr <luke-jr+eloipool@utopios.org>
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

import queue
import logging
from math import ceil, log
import networkserver
import socket
import struct
import threading
import time
import traceback
from util import target2avghashes, target2bdiff, target2pdiff

class DyntargetManager:
	logger = logging.getLogger('DyntargetManager')
	
	def __init__(self):
		self.userStatus = {}
	
	def clampTarget(self, target, DTMode):
		# ShareTarget is the minimum
		if target is None or target > self.ShareTarget:
			target = self.ShareTarget
		
		# Never target above the network, as we'd lose blocks
		if target < self.minTarget:
			target = self.minTarget
		
		if DTMode == 2:
			# Ceil target to a power of two :)
			truebits = log(target, 2)
			if target <= 2**int(truebits):
				# Workaround for bug in Python's math.log function
				truebits = int(truebits)
			target = 2**ceil(truebits) - 1
		elif DTMode == 3:
			# Round target to multiple of bdiff 1
			target = bdiff1target / int(round(target2bdiff(target)))
		
		# Return None for ShareTarget to save memory
		if target == self.ShareTarget:
			return None
		return target
	
	def resetShareCounter(self, username, now):
		self.userStatus[username][1] = now
		self.userStatus[username][2] = 0
	
	def getTargetLimits(self, username, now):
		userStatus = self.userStatus
		
		status = userStatus[username]
		(targetIn, lastUpdate, hashes) = status
		target = targetIn or self.ShareTarget
		work = hashes / target2avghashes(target)
		if work <= self.DynamicTargetGoal:
			if now < lastUpdate + self.DynamicTargetWindow and (targetIn is None or targetIn >= self.minTarget):
				# No reason to change it just yet
				return (targetIn, targetIn)
			if not work:
				# No shares received, reset to minimum
				if targetIn:
					self.logger.debug("No shares from %s, resetting to minimum target" % (repr(username),))
					self.resetShareCounter(username, now)
				return (None, None)
		
		deltaSec = now - lastUpdate
		target = int(target * self.DynamicTargetGoal * deltaSec / self.DynamicTargetWindow / work)
		self.resetShareCounter(username, now)
		return (target, target)
	
	def getTarget(self, username, now, DTMode = None, RequestedTarget = None):
		if DTMode is None:
			DTMode = self.DynamicTargetting
		if not DTMode:
			return None
		
		if username not in self.userStatus:
			self.userStatus[username] = [None, now, 0]
		targetIn = self.userStatus[username][0]
		
		(maxtarget, deftarget) = self.getTargetLimits(username, now)
		if RequestedTarget:
			target = min(maxtarget, RequestedTarget)
		else:
			target = deftarget
		target = self.clampTarget(target, DTMode)
		
		if target != targetIn:
			self.userStatus[username][0] = target
			pfx = 'Retargetting %s' % (repr(username),)
			tin = targetIn or self.ShareTarget
			self.logger.debug("%s from: %064x (pdiff %s)" % (pfx, tin, target2pdiff(tin)))
			tgt = target or self.ShareTarget
			self.logger.debug("%s   to: %064x (pdiff %s)" % (pfx, tgt, target2pdiff(tgt)))
		
		return target
	
	def TopTargets(self, n = 0x10):
		userStatus = self.userStatus
		
		tmp = list(k for k, v in userStatus.items() if not v[0] is None)
		tmp.sort(key=lambda k: -userStatus[k][0])
		tmp2 = {}
		def t2d(t):
			if t not in tmp2:
				tmp2[t] = target2pdiff(t)
			return tmp2[t]
		for k in tmp[-n:]:
			tgt = userStatus[k][0]
			print('%-34s %064x %3d' % (k, tgt, t2d(tgt)))
	
	def workCompleted(self, username, hashes):
		if self.DynamicTargetting and username in self.userStatus:
			# NOTE: userStatus[username] only doesn't exist across restarts
			self.userStatus[username][2] += hashes

class DyntargetClient(networkserver.SocketHandler):
	logger = logging.getLogger('DyntargetClient')
	
	def __init__(self, *a, UpstreamManager=None, **ka):
		super().__init__(*a, **ka)
		self.UsMgr = UpstreamManager
		self.push(b'Dyntarget Client 0\0')
		self.set_terminator(b'\0')
		self.waitingfor = {}
	
	def process_data(self, inbuf):
		# NOTE: Replaced after version negotiation
		assert inbuf[:17] == b'Dyntarget Server '
		self.changeTask(None)
		self.reset_process()
	
	def close(self):
		try:
			raise None
		except:
			print(traceback.format_exc())
	
	def reset_process(self):
		self.process_data = self.process_targets
		self.set_terminator(65)
		print("RESET")
	
	def process_targets(self, inbuf):
		assert inbuf[0:1] == b'\1'
		nl = struct.unpack('!8Q', inbuf[1:])
		self.maxtarget = (nl[0] << 192) | (nl[1] << 128) | (nl[2] << 64) | nl[3]
		self.deftarget = (nl[4] << 192) | (nl[5] << 128) | (nl[6] << 64) | nl[7]
		print("Got targets")
		
		self.process_data = self.process_username
		self.set_terminator(b'\0')
	
	def process_username(self, inbuf):
		busername = inbuf
		username = busername.decode('utf8')
		print("Got username %s"% (username,))
		rv = (self.maxtarget, self.deftarget)
		self.UsMgr.setTargetLimits(username, *rv)
		wf = self.waitingfor.get(username)
		if wf:
			del self.waitingfor[username]
			for rq in wf:
				rq.put(rv)
		
		self.reset_process()
	
	def close(self):
		super().close()
		self.client._reconnect()

class DyntargetClientMain(networkserver.AsyncSocketServer):
	logger = logging.getLogger('DyntargetClientMain')

class DyntargetManagerRemote(DyntargetManager):
	def __init__(self, *a, **ka):
		super().__init__(*a, **ka)
		self._main = DyntargetClientMain(DyntargetClient)
		thr = threading.Thread(target=self._main.serve_forever)
		thr.daemon = True
		thr.start()
		self._thr = thr
		self.client = lambda: None
		self.client.fd = -1
	
	def _maybe_reconnect(self):
		if self.client.fd != -1:
			return
		self._reconnect()
	
	def _reconnect(self):
		dest = self.DynamicTargetServer
		sock = socket.socket(socket.AF_INET6)
		sock.connect(dest)
		self.client = DyntargetClient(self._main, sock, dest, UpstreamManager=self)
	
	def _getTargetLimits_I(self, username, now):
		self._maybe_reconnect()
		hashes = self.userStatus.get(username, (None, None, 0))[2]
		busername = username.encode('utf8')
		pkt = b'\0' + struct.pack('!Q', int(hashes)) + busername + b'\0'
		rq = queue.Queue(1)
		self.client.waitingfor.setdefault(username, []).append(rq)
		print("Waiting... %s" % (username,))
		self.client.push(pkt)
		
		rv = rq.get(timeout=1)
		self.resetShareCounter(username, now)
		return rv
	
	def getTargetLimits(self, username, *a, **ka):
		try:
			return self._getTargetLimits_I(username, *a, **ka)
		except:
			self.logger.warn(traceback.format_exc())
			pass
		
		target = self.userStatus.get(username, (None,))[0]
		return (target, target)
	
	def setTargetLimits(self, username, maxtarget, deftarget):
		pass
