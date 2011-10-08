from binascii import a2b_hex
from bitcoin.script import countSigOps
from bitcoin.txn import Txn
from collections import deque
from queue import Queue
import jsonrpc
import logging
from merkletree import MerkleTree
from struct import pack
import threading
from time import sleep, time
import traceback

_makeCoinbase = [0, 0]

class merkleMaker(threading.Thread):
	def __init__(self, *a, **k):
		super().__init__(*a, **k)
		self.daemon = True
		self.logger = logging.getLogger('merkleMaker')
		self.CoinbasePrefix = b''
	
	def _prepare(self):
		self.access = jsonrpc.ServiceProxy(self.UpstreamURI)
		
		self.currentBlock = (None, None)
		self.currentMerkleTree = None
		self.merkleRoots = deque(maxlen=self.WorkQueueSizeRegular[1])
		self.clearMerkleTree = MerkleTree([self.clearCoinbaseTxn])
		self.clearMerkleRoots = Queue(self.WorkQueueSizeLongpoll[1])
		
		self.nextMerkleUpdate = 0
		global now
		now = time()
		self.updateMerkleTree()
	
	def updateMerkleTree(self):
		global now
		self.logger.debug('Polling bitcoind for memorypool')
		self.nextMerkleUpdate = now + self.TxnUpdateRetryWait
		MP = self.access.getmemorypool()
		prevBlock = a2b_hex(MP['previousblockhash'])[::-1]
		if prevBlock != self.currentBlock[0]:
			self.logger.debug('New block: %s' % (MP['previousblockhash'],))
			self.merkleRoots.clear()
			self.currentMerkleTree = self.clearMerkleTree
			bits = a2b_hex(MP['bits'])[::-1]
			self.lastBlock = self.currentBlock
			self.currentBlock = (prevBlock, bits)
			self.onBlockChange()
		# TODO: cache Txn or at least txid from previous merkle roots?
		txnlist = [a for a in map(a2b_hex, MP['transactions'])]
		
		t = self.makeCoinbaseTxn(MP['coinbasevalue'])
		t.setCoinbase(b'\0\0')
		t.assemble()
		txnlist.insert(0, t.data)
		
		txnlistsz = sum(map(len, txnlist))
		while txnlistsz > 934464:  # TODO: 1 "MB" limit - 64 KB breathing room
			self.logger.debug('Trimming transaction for size limit')
			txnlistsz -= len(txnlist.pop())
		
		txnlistsz = sum(map(countSigOps, txnlist))
		while txnlistsz > 19488:  # TODO: 20k limit - 0x200 breathing room
			self.logger.debug('Trimming transaction for SigOp limit')
			txnlistsz -= countSigOps(txnlist.pop())
		
		txnlist = [a for a in map(Txn, txnlist[1:])]
		txnlist.insert(0, t)
		txnlist = list(txnlist)
		newMerkleTree = MerkleTree(txnlist)
		if newMerkleTree.merkleRoot() != self.currentMerkleTree.merkleRoot():
			self.logger.debug('Updating merkle tree')
			self.currentMerkleTree = newMerkleTree
		self.nextMerkleUpdate = now + self.MinimumTxnUpdateWait
	
	def makeCoinbase(self):
		now = int(time())
		if now > _makeCoinbase[0]:
			_makeCoinbase[0] = now
			_makeCoinbase[1] = 0
		else:
			_makeCoinbase[1] += 1
		return self.CoinbasePrefix + pack('>L', now) + pack('>Q', _makeCoinbase[1]).lstrip(b'\0')
	
	def makeMerkleRoot(self, merkleTree):
		t = merkleTree.data[0]
		cb = self.makeCoinbase()
		t.setCoinbase(cb)
		t.assemble()
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
	
	def merkleMaker_I(self):
		global now
		
		# First, update merkle tree if we haven't for a while and aren't crunched for time
		now = time()
		if self.nextMerkleUpdate <= now and self.clearMerkleRoots.qsize() > self.WorkQueueSizeLongpoll[0] and len(self.merkleRoots) > self.WorkQueueSizeRegular[0]:
			self.updateMerkleTree()
		# Next, fill up the longpoll queue first, since it can be used as a failover for the main queue
		elif not self.clearMerkleRoots.full():
			self._doing('blank merkle roots')
			self.clearMerkleRoots.put(self.makeMerkleRoot(self.clearMerkleTree))
		# Next, fill up the main queue (until they're all current)
		elif len(self.merkleRoots) < self.WorkQueueSizeRegular[1] or self.merkleRoots[0][1] != self.currentMerkleTree:
			self._doing('regular merkle roots')
			self.merkleRoots.append(self.makeMerkleRoot(self.currentMerkleTree))
		else:
			self._doing('idle')
			# TODO: rather than sleepspin, block until MinimumTxnUpdateWait expires or threading.Condition(?)
			sleep(self.IdleSleepTime)
	
	def run(self):
		while True:
			try:
				self.merkleMaker_I()
				self._THISISUGLY._flushrecv()
			except:
				self.logger.critical(traceback.format_exc())
	
	def start(self, *a, **k):
		self._prepare()
		super().start(*a, **k)
	
	def getMRD(self):
		(prevBlock, bits) = self.currentBlock
		try:
			MRD = self.merkleRoots.pop()
			rollPrevBlk = False
		except IndexError:
			MRD = self.clearMerkleRoots.get()
			rollPrevBlk = True
		(merkleRoot, merkleTree, cb) = MRD
		return (merkleRoot, merkleTree, cb, prevBlock, bits, rollPrevBlk)
