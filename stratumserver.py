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

from binascii import b2a_hex
import collections
from copy import deepcopy
import json
import logging
import networkserver
#import re
import struct
from time import time
#import traceback
from util import RejectedShare, swap32, target2bdiff

class StratumError(BaseException):
	def __init__(self, errno, msg):
		self.StratumErrNo = errno
		self.StratumErrMsg = msg

StratumCodes = {
	'stale-prevblk': 21,
	'stale-work': 21,
	'duplicate': 22,
	'H-not-zero': 23,
	'high-hash': 23,
}

class StratumHandler(networkserver.SocketHandler):
	logger = logging.getLogger('StratumHandler')
	
	def __init__(self, *a, **ka):
		super().__init__(*a, **ka)
		self.remoteHost = self.addr[0]
		self.changeTask(None)
		self.set_terminator(b"\n")
		self.Usernames = {}
		self.lastBDiff = None
		self.JobTargets = collections.OrderedDict()
	
	def sendReply(self, ob):
		return self.push(json.dumps(ob).encode('ascii') + b"\n")
	
	def found_terminator(self):
		inbuf = b"".join(self.incoming).decode('ascii')
		self.incoming = []
		
		if not inbuf:
			return
		
		rpc = json.loads(inbuf)
		funcname = '_stratum_%s' % (rpc['method'].replace('.', '_'),)
		if not hasattr(self, funcname):
			self.sendReply({
				'error': [-3, "Method '%s' not found" % (rpc['method'],), None],
				'id': rpc['id'],
				'result': None,
			})
			return
		
		try:
			rv = getattr(self, funcname)(*rpc['params'])
		except StratumError as e:
			self.sendReply({
				'error': (e.StratumErrNo, e.StratumErrMsg, None),
				'id': rpc['id'],
				'result': None,
			})
			return
		
		self.sendReply({
			'error': None,
			'id': rpc['id'],
			'result': rv,
		})
	
	def sendJob(self):
		target = self.server.defaultTarget
		if len(self.Usernames) == 1:
			dtarget = self.server.getTarget(self.Usernames[0], time(), 3)
			if not target is None:
				target = dtarget
		bdiff = target2bdiff(target)
		if self.lastBDiff != bdiff:
			self.sendReply({
				'id': None,
				'method': 'mining.set_difficulty',
				'params': [
					bdiff
				],
			})
			self.lastBDiff = bdiff
		self.push(self.server.JobBytes)
		if len(self.JobTargets) > 4:
			self.JobTargets.popitem(False)
		self.JobTargets[self.server.JobId] = target
	
	def _stratum_mining_subscribe(self):
		xid = struct.pack('@P', id(self))
		self.extranonce1 = xid
		xid = b2a_hex(xid).decode('ascii')
		self.server._Clients[id(self)] = self
		self.changeTask(self.sendJob, 0)
		return [
			[
				['mining.notify', '%s1' % (xid,)],
				['mining.set_difficulty', '%s2' % (xid,)],
			],
			xid,
			4,
		]
	
	def handle_close(self):
		try:
			del self.server._Clients[id(self)]
		except:
			pass
		super().handle_close()
	
	def _stratum_mining_submit(self, username, jobid, extranonce2, ntime, nonce):
		if username not in self.Usernames:
			raise StratumError(24, 'unauthorized-user')
		share = {
			'username': username,
			'remoteHost': self.remoteHost,
			'jobid': jobid,
			'extranonce1': self.extranonce1,
			'extranonce2': bytes.fromhex(extranonce2),
			'ntime': bytes.fromhex(ntime),
			'nonce': bytes.fromhex(nonce),
		}
		if jobid in self.JobTargets:
			share['target'] = self.JobTargets[jobid]
		try:
			self.server.receiveShare(share)
		except RejectedShare as rej:
			rej = str(rej)
			errno = StratumCodes.get(rej, 20)
			raise StratumError(errno, rej)
		return True
	
	def checkAuthentication(self, username, password):
		return True
	
	def _stratum_mining_authorize(self, username, password = None):
		try:
			valid = self.checkAuthentication(username, password)
		except:
			valid = False
		if valid:
			self.Usernames[username] = None
		return valid
	
	def _stratum_mining_get_transactions(self, jobid):
		(MC, wld) = self.server.getExistingStratumJob(jobid)
		(height, merkleTree, cb, prevBlock, bits) = MC[:5]
		return list(b2a_hex(txn.data).decode('ascii') for txn in merkleTree.data[1:])

class StratumServer(networkserver.AsyncSocketServer):
	logger = logging.getLogger('StratumServer')
	
	waker = True
	
	extranonce1null = struct.pack('@P', 0)
	
	def __init__(self, *a, **ka):
		ka.setdefault('RequestHandlerClass', StratumHandler)
		super().__init__(*a, **ka)
		
		self._Clients = {}
		self._JobId = 0
		self.JobId = '%d' % (time(),)
		self.WakeRequest = None
		self.UpdateTask = None
	
	def updateJob(self, wantClear = False):
		if self.UpdateTask:
			try:
				self.rmSchedule(self.UpdateTask)
			except:
				pass
		
		self._JobId += 1
		JobId = '%d %d' % (time(), self._JobId)
		(MC, wld) = self.getStratumJob(JobId, wantClear=wantClear)
		(height, merkleTree, cb, prevBlock, bits) = MC[:5]
		
		if len(cb) > 96 - len(self.extranonce1null) - 4:
			self.logger.warning('Coinbase too big for Stratum: GIVING CLIENTS INVALID JOBS')
			# TODO: shutdown stratum
			# TODO: restart automatically when coinbase works?
		
		txn = deepcopy(merkleTree.data[0])
		cb += self.extranonce1null + b'Eloi'
		txn.setCoinbase(cb)
		txn.assemble()
		pos = txn.data.index(cb) + len(cb)
		
		steps = list(b2a_hex(h).decode('ascii') for h in merkleTree._steps)
		
		self.JobBytes = json.dumps({
			'id': None,
			'method': 'mining.notify',
			'params': [
				JobId,
				b2a_hex(swap32(prevBlock)).decode('ascii'),
				b2a_hex(txn.data[:pos - len(self.extranonce1null) - 4]).decode('ascii'),
				b2a_hex(txn.data[pos:]).decode('ascii'),
				steps,
				'00000002',
				b2a_hex(bits[::-1]).decode('ascii'),
				b2a_hex(struct.pack('>L', int(time()))).decode('ascii'),
				False
			],
		}).encode('ascii') + b"\n"
		self.JobId = JobId
		
		self.WakeRequest = 1
		self.wakeup()
		
		self.UpdateTask = self.schedule(self.updateJob, time() + 30)
	
	def pre_schedule(self):
		if self.WakeRequest:
			self._wakeNodes()
	
	def _wakeNodes(self):
		self.WakeRequest = None
		C = self._Clients
		if not C:
			self.logger.debug('Nobody to wake up')
			return
		OC = len(C)
		self.logger.debug("%d clients to wake up..." % (OC,))
		
		now = time()
		
		for ic in list(C.values()):
			try:
				ic.sendJob()
			except socket.error:
				OC -= 1
				# Ignore socket errors; let the main event loop take care of them later
			except:
				OC -= 1
				self.logger.debug('Error sending new job:\n' + traceback.format_exc())
		
		self.logger.debug('New job sent to %d clients in %.3f seconds' % (OC, time() - now))
	
	def getTarget(*a, **ka):
		return None
