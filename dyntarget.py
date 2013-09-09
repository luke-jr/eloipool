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

import logging
from math import ceil, log
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
	
	def getTarget(self, username, now, DTMode = None, RequestedTarget = None):
		userStatus = self.userStatus
		
		if DTMode is None:
			DTMode = self.DynamicTargetting
		if not DTMode:
			return None
		if username in userStatus:
			status = userStatus[username]
		else:
			# No record, use default target
			RequestedTarget = self.clampTarget(RequestedTarget, DTMode)
			userStatus[username] = [RequestedTarget, now, 0]
			return RequestedTarget
		(targetIn, lastUpdate, hashes) = status
		target = targetIn or self.ShareTarget
		work = hashes / target2avghashes(target)
		if work <= self.DynamicTargetGoal:
			if now < lastUpdate + self.DynamicTargetWindow and (targetIn is None or targetIn >= self.minTarget):
				# No reason to change it just yet
				return self.clampTarget(targetIn, DTMode)
			if not work:
				# No shares received, reset to minimum
				if targetIn:
					self.logger.debug("No shares from %s, resetting to minimum target" % (repr(username),))
					userStatus[username] = [None, now, 0]
				return self.clampTarget(None, DTMode)
		
		deltaSec = now - lastUpdate
		target = int(target * self.DynamicTargetGoal * deltaSec / self.DynamicTargetWindow / work)
		target = self.clampTarget(target, DTMode)
		if target != targetIn:
			pfx = 'Retargetting %s' % (repr(username),)
			tin = targetIn or self.ShareTarget
			self.logger.debug("%s from: %064x (pdiff %s)" % (pfx, tin, target2pdiff(tin)))
			tgt = target or self.ShareTarget
			self.logger.debug("%s   to: %064x (pdiff %s)" % (pfx, tgt, target2pdiff(tgt)))
		userStatus[username] = [target, now, 0]
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
