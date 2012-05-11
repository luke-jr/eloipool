from binascii import a2b_hex
from bitcoin.script import countSigOps
from bitcoin.txn import Txn
from collections import deque
from queue import Queue
import jsonrpc
import logging
from merkletree import MerkleTree
import threading
from time import sleep, time
import traceback

clearMerkleTree = MerkleTree([None])
clearMerkleTree.coinbaseValue = 5000000000  # FIXME

class merkleMaker(threading.Thread):
	def __init__(self, *a, **k):
		super().__init__(*a, **k)
		self.daemon = True
		self.logger = logging.getLogger('merkleMaker')
	
	def _prepare(self):
		self.access = jsonrpc.ServiceProxy(self.UpstreamURI)
		
		self.currentBlock = (None, None)
		self.currentMerkleTree = None
		self.merkleRoots = deque(maxlen=self.WorkQueueSizeRegular[1])
		self.clearMerkleRoots = Queue(self.WorkQueueSizeLongpoll[1])
		
		self.nextMerkleUpdate = 0
		self.lastWarning = {}
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
			tmpMT = MerkleTree([None])
			tmpMT.coinbaseValue = 5000000000  # FIXME
			self.currentMerkleTree = tmpMT
			bits = a2b_hex(MP['bits'])[::-1]
			self.lastBlock = self.currentBlock
			self.currentBlock = (prevBlock, bits)
			self.onBlockChange()
		# TODO: cache Txn or at least txid from previous merkle roots?
		txnlist = map(a2b_hex, MP['transactions'])
		
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
		
		txnlist = map(Txn, txnlist)
		txnlist = [None] + list(txnlist)
		newMerkleTree = MerkleTree(txnlist)
		if newMerkleTree.withFirst(b'') != self.currentMerkleTree.withFirst(b''):
			self.logger.debug('Updating merkle tree')
			newMerkleTree.coinbaseValue = MP['coinbasevalue']
			self.currentMerkleTree = newMerkleTree
		self.nextMerkleUpdate = now + self.MinimumTxnUpdateWait
	
	def makeMerkleRoot(self, merkleTree):
		coinbaseTxn = self.makeCoinbaseTxn(merkleTree.coinbaseValue)
		merkleRoot = merkleTree.withFirst(coinbaseTxn)
		return (merkleRoot, merkleTree, coinbaseTxn)
	
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
		if self.nextMerkleUpdate <= now and self.clearMerkleRoots.qsize() > self.WorkQueueSizeLongpoll[0] and len(self.merkleRoots) > self.WorkQueueSizeRegular[0]:
			self.updateMerkleTree()
		# Next, fill up the longpoll queue first, since it can be used as a failover for the main queue
		elif not self.clearMerkleRoots.full():
			self._doing('blank merkle roots')
			self.clearMerkleRoots.put(self.makeMerkleRoot(clearMerkleTree))
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
		(merkleRoot, merkleTree, coinbaseTxn) = MRD
		return (merkleRoot, merkleTree, coinbaseTxn, prevBlock, bits, rollPrevBlk)
