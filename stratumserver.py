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

from binascii import b2a_hex
import collections
from copy import deepcopy
import json
import logging
import networkserver
import os
import pickle
import socket
import struct
from time import time
import traceback
from util import RejectedShare, swap32, target2bdiff, UniqueSessionIdManager

class StratumError(BaseException):
	def __init__(self, errno, msg, tb = True):
		self.StratumErrNo = errno
		self.StratumErrMsg = msg
		self.StratumTB = tb

StratumCodes = {
	'stale-prevblk': 21,
	'stale-work': 21,
	'duplicate': 22,
	'H-not-zero': 23,
	'high-hash': 23,
}

_exported_sockets = []

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
		self.UA = None
	
	def _export(self):
		if hasattr(self, '_sid'):
			UniqueSessionIdManager.put(self._sid, delay=True)
		subscribed = id(self) in self.server._Clients
		self._unlink()
		
		data = self.__dict__
		_exported_sockets.append(data['socket'])  # Or the destructor will close the socket on us :(
		del data['socket']
		del data['server']
		if data.get('_Task'): data['_Task'] = data['_Task'].__func__.__name__
		if not subscribed: data['_not_subscribed'] = None
		
		data = pickle.dumps(data)
		return data
	
	@classmethod
	def _import(cls, server, data):
		data = pickle.loads(data)
		sock = socket.fromfd(data['fd'], socket.AF_INET6, socket.SOCK_STREAM)
		
		# Python dups the fd we give it, so close the old one and use the new one
		os.close(data['fd'])
		data['fd'] = sock.fileno()
		
		self = cls(server, sock, data['addr'])
		self.__dict__ = data
		self.server = server
		self.socket = sock
		if getattr(self, '_Task', None): self.changeTask(getattr(self, self._Task), 0)
		if hasattr(self, '_sid'):
			try:
				UniqueSessionIdManager.getSpecific(self._sid, unlimited=True)
			except KeyError:
				del self._sid
				self.logger.error('Failed to restore same session id, disconnecting')
				self.boot()
		if hasattr(self, '_not_subscribed'):
			del self._not_subscribed
			self.server._Clients[id(self)] = self
	
	def sendReply(self, ob):
		return self.push(json.dumps(ob).encode('ascii') + b"\n")
	
	def found_terminator(self):
		inbuf = b"".join(self.incoming).decode('ascii')
		self.incoming = []
		
		if not inbuf:
			return
		
		try:
			rpc = json.loads(inbuf)
		except ValueError:
			self.boot()
			return
		if 'method' not in rpc:
			# Assume this is a reply to our request
			funcname = '_stratumreply_%s' % (rpc['id'],)
			if not hasattr(self, funcname):
				return
			try:
				getattr(self, funcname)(rpc)
			except BaseException as e:
				self.logger.debug(traceback.format_exc())
			return
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
				'error': (e.StratumErrNo, e.StratumErrMsg, traceback.format_exc() if e.StratumTB else None),
				'id': rpc['id'],
				'result': None,
			})
			return
		except BaseException as e:
			fexc = traceback.format_exc()
			self.sendReply({
				'error': (20, str(e), fexc),
				'id': rpc['id'],
				'result': None,
			})
			if not hasattr(e, 'StratumQuiet'):
				self.logger.debug(fexc)
			return
		
		self.sendReply({
			'error': None,
			'id': rpc['id'],
			'result': rv,
		})
	
	def sendJob(self):
		target = self.server.defaultTarget
		if len(self.Usernames) == 1:
			dtarget = self.server.getTarget(next(iter(self.Usernames)), time())
			if not dtarget is None:
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
	
	def requestStratumUA(self):
		self.sendReply({
			'id': 7,
			'method': 'client.get_version',
			'params': (),
		})
	
	def _stratumreply_7(self, rpc):
		self.UA = rpc.get('result') or rpc
	
	def _stratum_mining_subscribe(self, UA = None, xid = None):
		if not UA is None:
			self.UA = UA
		if not hasattr(self, '_sid'):
			self._sid = UniqueSessionIdManager.get()
		if self.server._Clients.get(self._sid) not in (self, None):
			del self._sid
			raise self.server.RaiseRedFlags(RuntimeError('issuing duplicate sessionid'))
		xid = struct.pack('=I', self._sid)  # NOTE: Assumes sessionids are 4 bytes
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
	
	def _unlink(self):
		try:
			del self.server._Clients[id(self)]
		except:
			pass
		super()._unlink()
	
	def close(self):
		if hasattr(self, '_sid'):
			UniqueSessionIdManager.put(self._sid)
			delattr(self, '_sid')
		super().close()
	
	def _stratum_mining_submit(self, username, jobid, extranonce2, ntime, nonce):
		if username not in self.Usernames:
			raise StratumError(24, 'unauthorized-user', False)
		share = {
			'username': username,
			'remoteHost': self.remoteHost,
			'jobid': jobid,
			'extranonce1': self.extranonce1,
			'extranonce2': bytes.fromhex(extranonce2),
			'ntime': bytes.fromhex(ntime),
			'nonce': bytes.fromhex(nonce),
			'userAgent': self.UA,
			'submitProtocol': 'stratum',
		}
		if jobid in self.JobTargets:
			share['target'] = self.JobTargets[jobid]
		try:
			self.server.receiveShare(share)
		except RejectedShare as rej:
			rej = str(rej)
			errno = StratumCodes.get(rej, 20)
			raise StratumError(errno, rej, False)
		return True
	
	def _stratum_mining_authorize(self, username, password = None):
		try:
			valid = self.server.checkAuthentication(username, password)
		except:
			valid = False
		if valid:
			self.Usernames[username] = None
			self.changeTask(self.requestStratumUA, 0)
		return valid
	
	def _stratum_mining_get_transactions(self, jobid):
		try:
			(MC, wld) = self.server.getExistingStratumJob(jobid)
		except KeyError as e:
			e.StratumQuiet = True
			raise
		(height, merkleTree, cb, prevBlock, bits) = MC[:5]
		return list(b2a_hex(txn.data).decode('ascii') for txn in merkleTree.data[1:])

class StratumServer(networkserver.AsyncSocketServer):
	logger = logging.getLogger('StratumServer')
	
	waker = True
	schMT = True
	
	extranonce1null = struct.pack('=I', 0)  # NOTE: Assumes sessionids are 4 bytes
	
	def __init__(self, *a, **ka):
		ka.setdefault('RequestHandlerClass', StratumHandler)
		super().__init__(*a, **ka)
		
		self._Clients = {}
		self._JobId = 0
		self.JobId = '%d' % (time(),)
		self.WakeRequest = None
		self.UpdateTask = None
	
	def shutdown(self):
		if hasattr(self, 'sessiondata') and self.connections:
			# Export all active handlers
			hlist = list(self.connections.values())
			for h in hlist:
				data = h._export()
				self.sessiondata.append(data)
	
	def _restoresession(self, sessiondata):
		if not sessiondata:
			return
		if not os.environ.get('__ELOIPOOL_EXECD'):
			self.logger.warning('Ignoring saved socket data (not launched by restart func)')
			return
		for data in sessiondata:
			self.RequestHandlerClass._import(self, data)
		self.logger.info('Restored %s active sockets' % (len(sessiondata),))
	
	def checkAuthentication(self, username, password):
		return True
	
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
			if not self.rejecting:
				self.logger.warning('Coinbase too big for stratum: disabling')
			self.rejecting = True
			self.boot_all()
			self.UpdateTask = self.schedule(self.updateJob, time() + 10)
			return
		elif self.rejecting:
			self.rejecting = False
			self.logger.info('Coinbase small enough for stratum again: reenabling')
		
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
				not self.IsJobValid(self.JobId)
			],
		}).encode('ascii') + b"\n"
		self.JobId = JobId
		
		self.WakeRequest = 1
		self.wakeup()
		
		self.UpdateTask = self.schedule(self.updateJob, time() + 55)
	
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
