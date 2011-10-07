from binascii import a2b_hex
from bitcointxn import Txn
from collections import deque
from queue import Queue
import jsonrpc
from merkletree import MerkleTree
import threading
from time import sleep, time
import traceback
import sys # for debugging

clearMerkleTree = MerkleTree([None])

class merkleMaker(threading.Thread):
	def __init__(self, *a, **k):
		super().__init__(*a, **k)
		self.daemon = True
	
	def _prepare(self):
		self.access = jsonrpc.ServiceProxy(self.UpstreamURI)
		
		self.currentBlock = (None, None)
		self.currentMerkleTree = None
		self.merkleRoots = deque(maxlen=self.WorkQueueSizeRegular[1])
		self.clearMerkleRoots = Queue(self.WorkQueueSizeLongpoll[1])
		
		self.nextMerkleUpdate = 0
		global now
		now = time()
		self.updateMerkleTree()
	
	def updateMerkleTree(self):
		sys.stdout.write("\nUPDATE ")
		global now
		self.nextMerkleUpdate = now + self.TxnUpdateRetryWait
		MP = self.access.getmemorypool()
		prevBlock = a2b_hex(MP['previousblockhash'])[::-1]
		if prevBlock != self.currentBlock[0]:
			self.merkleRoots.clear()
			self.currentMerkleTree = MerkleTree([None])
			bits = a2b_hex(MP['bits'])[::-1]
			self.lastBlock = self.currentBlock
			self.currentBlock = (prevBlock, bits)
			self.onBlockChange()
		# TODO: cache Txn or at least txid from previous merkle roots?
		txnlist = map(Txn, map(a2b_hex, MP['transactions']))
		txnlist = [None] + list(txnlist)
		newMerkleTree = MerkleTree(txnlist)
		if newMerkleTree.withFirst(b'') != self.currentMerkleTree.withFirst(b''):
			self.currentMerkleTree = newMerkleTree
		self.nextMerkleUpdate = now + self.MinimumTxnUpdateWait
	
	def makeMerkleRoot(self, merkleTree):
		coinbaseTxn = self.makeCoinbaseTxn()
		merkleRoot = merkleTree.withFirst(coinbaseTxn)
		return (merkleRoot, merkleTree, coinbaseTxn)
	
	def merkleMaker_I(self):
		global now
		
		# First, update merkle tree if we haven't for a while and aren't crunched for time
		now = time()
		if self.nextMerkleUpdate <= now and self.clearMerkleRoots.qsize() > self.WorkQueueSizeLongpoll[0] and len(self.merkleRoots) > self.WorkQueueSizeRegular[0]:
			self.updateMerkleTree()
		# Next, fill up the longpoll queue first, since it can be used as a failover for the main queue
		elif not self.clearMerkleRoots.full():
			sys.stdout.write("CLR ")
			self.clearMerkleRoots.put(self.makeMerkleRoot(clearMerkleTree))
		# Next, fill up the main queue (until they're all current)
		elif len(self.merkleRoots) < self.WorkQueueSizeRegular[1] or self.merkleRoots[0][1] != self.currentMerkleTree:
			sys.stdout.write("REG ")
			self.merkleRoots.append(self.makeMerkleRoot(self.currentMerkleTree))
		else:
			sys.stdout.write(".")
			# TODO: rather than sleepspin, block until MinimumTxnUpdateWait expires or threading.Condition(?)
			sleep(self.IdleSleepTime)
		sys.stdout.flush()
	
	def run(self):
		while True:
			try:
				self.merkleMaker_I()
			except:
				print(traceback.format_exc())
	
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
