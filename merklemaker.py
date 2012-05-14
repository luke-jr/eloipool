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
from bitcoin.script import countSigOps
from bitcoin.txn import Txn
from collections import deque
from queue import Queue
import jsonrpc
import logging
from math import log
from merkletree import MerkleTree
from struct import pack
import threading
from time import sleep, time
import traceback
from util import BEhash2int, Bits2Target

_makeCoinbase = [0, 0]

class merkleMaker(threading.Thread):
	def __init__(self, *a, **k):
		super().__init__(*a, **k)
		self.daemon = True
		self.logger = logging.getLogger('merkleMaker')
		self.CoinbasePrefix = b''
		self.CoinbaseAux = {}
		self.isOverflowed = False
		self.overflowed = 0
	
	def _prepare(self):
		self.access = jsonrpc.ServiceProxy(self.UpstreamURI)
		
		self.currentBlock = (None, None)
		self.currentMerkleTree = None
		self.merkleRoots = deque(maxlen=self.WorkQueueSizeRegular[1])
		self.LowestMerkleRoots = self.WorkQueueSizeRegular[1]
		self.clearMerkleTree = MerkleTree([self.clearCoinbaseTxn])
		self.clearMerkleTree.upstreamTarget = (2 ** 224) - 1
		self.clearMerkleTree.coinbasePrefix = b''
		self.clearMerkleRoots = Queue(max(self.WorkQueueSizeLongpoll[1], 1))
		self.LowestClearMerkleRoots = self.WorkQueueSizeLongpoll[1]
		
		if not hasattr(self, 'WarningDelay'):
			self.WarningDelay = max(15, self.MinimumTxnUpdateWait * 2)
		if not hasattr(self, 'WarningDelayTxnLongpoll'):
			self.WarningDelayTxnLongpoll = self.WarningDelay
		if not hasattr(self, 'WarningDelayMerkleUpdate'):
			self.WarningDelayMerkleUpdate = self.WarningDelay
		
		self.lastMerkleUpdate = 0
		self.nextMerkleUpdate = 0
		self.lastWarning = {}
		global now
		now = time()
		self.updateMerkleTree()
	
	def updateBlock(self, newBlock, bits = None, _HBH = None):
		if newBlock == self.currentBlock[0]:
			if bits in (None, self.currentBlock[1]):
				return
			self.logger.error('Was working on block with wrong specs: %s (bits: %s->%s)' % (
				b2a_hex(newBlock[::-1]).decode('utf8'),
				b2a_hex(self.currentBlock[1][::-1]).decode('utf8'),
				b2a_hex(bits[::-1]).decode('utf8'),
			))
		
		if bits is None:
			bits = self.currentBlock[1]
		if _HBH is None:
			_HBH = (b2a_hex(newBlock[::-1]).decode('utf8'), b2a_hex(bits[::-1]).decode('utf8'))
		self.logger.info('New block: %s (bits: %s)' % _HBH)
		self.merkleRoots.clear()
		self.currentMerkleTree = self.clearMerkleTree
		if self.currentBlock[0] != newBlock:
			self.lastBlock = self.currentBlock
		self.currentBlock = (newBlock, bits)
		self.clearMerkleTree.upstreamTarget = max(self.clearMerkleTree.upstreamTarget, Bits2Target(bits))
		self.needMerkle = 2
		self.onBlockChange()
	
	def updateMerkleTree(self):
		global now
		self.logger.debug('Polling bitcoind for memorypool')
		self.nextMerkleUpdate = now + self.TxnUpdateRetryWait
		MP = self.access.getmemorypool()
		
		if 'coinbaseaux' in MP:
			for k, v in MP['coinbaseaux'].items():
				self.CoinbaseAux[k] = bytes.fromhex(v)
		
		if 'noncerange' in MP and MP['noncerange'] != '00000000ffffffff':
			self.logger.critical('Upstream has restricted noncerange; this is not supported!')
			raise RuntimeError('noncerange restricted')
		
		prevBlock = bytes.fromhex(MP['previousblockhash'])[::-1]
		bits = bytes.fromhex(MP['bits'])[::-1]
		if (prevBlock, bits) != self.currentBlock:
			self.updateBlock(prevBlock, bits, _HBH=(MP['previousblockhash'], MP['bits']))
		# TODO: cache Txn or at least txid from previous merkle roots?
		txnlist = [a for a in map(bytes.fromhex, MP['transactions'])]
		
		if 'coinbasetxn' in MP:
			mutable = MP.get('mutable', ())
			tmpltxn = None
			if 'generation' in mutable:
				if 'coinbasevalue' in MP:
					cbval = MP['coinbasevalue']
				else:
					# Add up the outputs from coinbasetxn
					tmpltxn = Txn(MP['coinbasetxn'])
					tmpltxn.disassemble()
					cbval = 0
					for tmploutput in tmpltxn.outputs:
						cbval += tmploutput[0]
				cbtxn = self.makeCoinbaseTxn(cbval)
			else:
				cbtxn = Txn(bytes.fromhex(MP['coinbasetxn']))
				cbtxn.disassemble()
			if 'coinbase' in mutable:
				# Any coinbase we want
				cbpfx = b''
			elif 'coinbase/append' in mutable:
				if 'generation' in mutable:
					if tmpltxn is None:
						tmpltxn = Txn(MP['coinbasetxn'])
						tmpltxn.disassemble()
					tmplcb = tmpltxn.getCoinbase()
					if self.CoinbasePrefix in tmplcb:
						if not self.CoinbasePrefix:
							self.logger.critical('Upstream requires coinbase prefix; need a unique CoinbasePrefix configued to cope')
						elif len(self.CoinbasePrefix) < 4:
							self.logger.error('CoinbasePrefix appeared in upstream mandatory coinbase data; try making it longer')
						else:
							self.logger.error('CoinbasePrefix appeared in upstream mandatory coinbase data; better luck next time?')
						raise RuntimeError('upstream coinbase contained my prefix')
					cbpfx = tmplcb
				else:
					cbpfx = cbtxn.getCoinbase()
			else:
				# Can't change the coinbase data, but we can abuse a generation...
				# TODO
				self.logger.critical('Upstream does not allow modifying coinbase data; this is not supported!')
				raise RuntimeError
		else:
			cbtxn = self.makeCoinbaseTxn(MP['coinbasevalue'])
			cbpfx = b''
		cbtxn.setCoinbase(b'\0\0')
		cbtxn.assemble()
		txnlist.insert(0, cbtxn.data)
		
		txnlistsz = sum(map(len, txnlist))
		if txnlistsz > 934464:  # 1 "MB" limit - 64 KB breathing room
			# FIXME: Try to safely truncate the block
			W = 'Making blocks over 1 MB size limit (%d bytes)' % (txnlistsz,)
			self._floodWarning(now, 'SizeLimit', lambda: W, W, logf=self.logger.error)
		
		txnlistsz = sum(map(countSigOps, txnlist))
		if txnlistsz > 19488:  # 20k limit - 0x200 breathing room
			# FIXME: Try to safely truncate the block
			W = 'Making blocks over 20k SigOp limit (%d)' % (txnlistsz,)
			self._floodWarning(now, 'SigOpLimit', lambda: W, W, logf=self.logger.error)
		
		txncount = len(txnlist)
		idealtxncount = txncount
		if hasattr(self, 'Greedy') and self.Greedy and 'transactionfees' in MP:
			feeinfo = MP['transactionfees']
			feeinfo.insert(0, -MP['coinbasevalue'])
			# Aim to cut off extra zero-fee transactions on the end
			# NOTE: not cutting out ones intermixed, in case of dependencies
			feeinfoLen = len(feeinfo)
			if feeinfoLen > txncount:
				feeinfoLen = txncount
			elif feeinfoLen < txncount:
				idealtxncount -= txncount - feeinfoLen
			for i in range(feeinfoLen - 1, 0, -1):
				if feeinfo[i]:
					break
				idealtxncount -= 1
		
		pot = 2**int(log(idealtxncount, 2))
		if pot < idealtxncount:
			if pot * 2 <= txncount:
				pot *= 2
			else:
				pot = idealtxncount
				POTWarn = "Making merkle tree with %d transactions (ideal: %d; max: %d)" % (pot, idealtxncount, txncount)
				self._floodWarning(now, 'Non-POT', lambda: POTWarn, POTWarn)
		txnlist = txnlist[:pot]
		
		txnlist = [a for a in map(Txn, txnlist[1:])]
		txnlist.insert(0, cbtxn)
		txnlist = list(txnlist)
		newMerkleTree = MerkleTree(txnlist)
		self.clearMerkleTree.coinbasePrefix = newMerkleTree.coinbasePrefix = cbpfx
		
		if 'target' in MP:
			newMerkleTree.upstreamTarget = BEhash2int(bytes.fromhex(MP['target']))
		else:
			newMerkleTree.upstreamTarget = Bits2Target(bits)
		self.clearMerkleTree.upstreamTarget = newMerkleTree.upstreamTarget
		
		if newMerkleTree.merkleRoot() != self.currentMerkleTree.merkleRoot() or newMerkleTree.upstreamTarget != self.currentMerkleTree.upstreamTarget or newMerkleTree.coinbasePrefix != self.currentMerkleTree.coinbasePrefix:
			self.logger.debug('Updating merkle tree')
			self.currentMerkleTree = newMerkleTree
		self.lastMerkleUpdate = now
		self.nextMerkleUpdate = now + self.MinimumTxnUpdateWait
		
		if self.needMerkle == 2:
			self.needMerkle = 1
			self.needMerkleSince = now
	
	def makeCoinbase(self, pfx = b''):
		now = int(time())
		if now > _makeCoinbase[0]:
			_makeCoinbase[0] = now
			_makeCoinbase[1] = 0
		else:
			_makeCoinbase[1] += 1
		rv = pack('>L', now) + pack('>Q', _makeCoinbase[1]).lstrip(b'\0')
		# NOTE: Not using varlenEncode, since this is always guaranteed to be < 100
		rv = bytes( (len(rv),) ) + rv
		rv = pfx + self.CoinbasePrefix + rv
		for v in self.CoinbaseAux.values():
			if v not in pfx:
				rv += v
		if len(rv) > 100:
			t = time()
			if self.overflowed < t - 300:
				self.logger.warning('Overflowing coinbase data! %d bytes long' % (len(rv),))
				self.overflowed = t
				self.isOverflowed = True
			rv = rv[:100]
		else:
			self.isOverflowed = False
		return rv
	
	def makeMerkleRoot(self, merkleTree):
		cbtxn = merkleTree.data[0]
		cbpfx = merkleTree.coinbasePrefix
		cb = self.makeCoinbase(cbpfx)
		cbtxn.setCoinbase(cb)
		cbtxn.assemble()
		merkleRoot = merkleTree.merkleRoot()
		return (merkleRoot, merkleTree, cb)
	
	_doing_last = None
	def _doing(self, what):
		if self._doing_last == what:
			self._doing_i += 1
			return
		global now
		if self._doing_last:
			self.logger.debug("Switching from (%4dx in %5.3f seconds) %s => %s" % (self._doing_i, now - self._doing_s, self._doing_last, what))
		self._doing_last = what
		self._doing_i = 1
		self._doing_s = now
	
	def _floodWarning(self, now, wid, wmsgf, doin = True, logf = None):
		if doin is True:
			doin = self._doing_last
			def a(f = wmsgf):
				return lambda: "%s (doing %s)" % (f(), doin)
			wmsgf = a()
		winfo = self.lastWarning.setdefault(wid, [0, None])
		(lastTime, lastDoing) = winfo
		if now <= lastTime + max(5, self.MinimumTxnUpdateWait) and doin == lastDoing:
			return
		winfo[0] = now
		nowDoing = doin
		winfo[1] = nowDoing
		if logf is None:
			logf = self.logger.warning
		logf(wmsgf())
	
	def merkleMaker_I(self):
		global now
		
		# First, update merkle tree if we haven't for a while and aren't crunched for time
		now = time()
		if self.nextMerkleUpdate <= now and self.clearMerkleRoots.qsize() >= self.WorkQueueSizeLongpoll[0] and len(self.merkleRoots) >= self.WorkQueueSizeRegular[0]:
			self.updateMerkleTree()
		# Next, fill up the longpoll queue first, since it can be used as a failover for the main queue
		elif self.clearMerkleRoots.qsize() < self.WorkQueueSizeLongpoll[1]:
			self._doing('blank merkle roots')
			self.clearMerkleRoots.put(self.makeMerkleRoot(self.clearMerkleTree))
		# Next, fill up the main queue (until they're all current)
		elif len(self.merkleRoots) < self.WorkQueueSizeRegular[1] or self.merkleRoots[0][1] != self.currentMerkleTree:
			if self.needMerkle == 1 and len(self.merkleRoots) >= self.WorkQueueSizeRegular[1]:
				self.onBlockUpdate()
				self.needMerkle = False
			self._doing('regular merkle roots')
			self.merkleRoots.append(self.makeMerkleRoot(self.currentMerkleTree))
		else:
			if self.needMerkle == 1:
				self.onBlockUpdate()
				self.needMerkle = False
			self._doing('idle')
			# TODO: rather than sleepspin, block until MinimumTxnUpdateWait expires or threading.Condition(?)
			sleep(self.IdleSleepTime)
		if self.needMerkle == 1 and now > self.needMerkleSince + self.WarningDelayTxnLongpoll:
			self._floodWarning(now, 'NeedMerkle', lambda: 'Transaction-longpoll requested %d seconds ago, and still not ready. Is your server fast enough to keep up with your configured WorkQueueSizeRegular maximum?' % (now - self.needMerkleSince,))
		if now > self.nextMerkleUpdate + self.WarningDelayMerkleUpdate:
			self._floodWarning(now, 'MerkleUpdate', lambda: "Haven't updated the merkle tree in at least %d seconds! Is your server fast enough to keep up with your configured work queue minimums?" % (now - self.lastMerkleUpdate,))
	
	def run(self):
		while True:
			try:
				self.merkleMaker_I()
			except:
				self.logger.critical(traceback.format_exc())
	
	def start(self, *a, **k):
		self._prepare()
		super().start(*a, **k)
	
	def getMRD(self):
		(prevBlock, bits) = self.currentBlock
		try:
			MRD = self.merkleRoots.pop()
			self.LowestMerkleRoots = min(len(self.merkleRoots), self.LowestMerkleRoots)
			rollPrevBlk = False
		except IndexError:
			qsz = self.clearMerkleRoots.qsize()
			if qsz < 0x10:
				self.logger.warning('clearMerkleRoots running out! only %d left' % (qsz,))
			MRD = self.clearMerkleRoots.get()
			self.LowestClearMerkleRoots = min(self.clearMerkleRoots.qsize(), self.LowestClearMerkleRoots)
			rollPrevBlk = True
		(merkleRoot, merkleTree, cb) = MRD
		return (merkleRoot, merkleTree, cb, prevBlock, bits, rollPrevBlk)
	
	def getMC(self):
		(prevBlock, bits) = self.currentBlock
		mt = self.currentMerkleTree
		cbpfx = mt.coinbasePrefix
		cb = self.makeCoinbase(cbpfx)
		return (None, mt, cb, prevBlock, bits)
