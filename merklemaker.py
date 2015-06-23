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
import bitcoin.script
from bitcoin.script import countSigOps
from bitcoin.txn import Txn
from bitcoin.varlen import varlenEncode, varlenDecode
from collections import deque
from copy import deepcopy
from queue import Queue
import jsonrpc
import logging
from math import log
from merkletree import MerkleTree
import socket
from struct import pack
import threading
from time import sleep, time
import traceback

_makeCoinbase = [0, 0]
_filecounter = 0

def MakeBlockHeader(MRD, BlockVersionBytes):
	(merkleRoot, merkleTree, coinbase, prevBlock, bits) = MRD[:5]
	timestamp = pack('<L', int(time()))
	hdr = BlockVersionBytes + prevBlock + merkleRoot + timestamp + bits + b'iolE'
	return hdr

def assembleBlock(blkhdr, txlist):
	payload = blkhdr
	payload += varlenEncode(len(txlist))
	for tx in txlist:
		payload += tx.data
	return payload

class merkleMaker(threading.Thread):
	GBTCaps = [
		'coinbasevalue',
		'coinbase/append',
		'coinbase',
		'generation',
		'time',
		'transactions/remove',
		'prevblock',
	]
	GBTReq = {
		'capabilities': GBTCaps,
	}
	GMPReq = {
		'capabilities': GBTCaps,
		'tx': 'obj',
	}
	
	def __init__(self, *a, **k):
		super().__init__(*a, **k)
		self.daemon = True
		self.logger = logging.getLogger('merkleMaker')
		self.CoinbasePrefix = b''
		self.CoinbaseAux = {}
		self.isOverflowed = False
		self.lastWarning = {}
		self.MinimumTxnUpdateWait = 5
		self.overflowed = 0
		self.DifficultyChangeMod = 2016
		self.MinimumTemplateAcceptanceRatio = 0
		self.MinimumTemplateScore = 1
		self.currentBlock = (None, None, None)
		self.lastBlock = (None, None, None)
		self.SubsidyAlgo = lambda height: 5000000000 >> (height // 210000)
	
	def _prepare(self):
		self.UseTemplateChecks = True
		if getattr(self, 'TemplateChecks', True) is None:
			self.TemplateChecks = ()
			self.UseTemplateChecks = False
		self.TemplateSources = list(getattr(self, 'TemplateSources', ()))
		self.TemplateChecks = list(getattr(self, 'TemplateChecks', ()))
		if getattr(self, 'BlockSubmissions', None) is None:
			self.BlockSubmissions = ()
		if hasattr(self, 'UpstreamURI'):
			self.TemplateSources.append({
				'name': 'UpstreamURI',
				'uri': self.UpstreamURI,
			})
		URI2Name = {}
		Name2URI = {}
		for a in (self.TemplateSources + self.TemplateChecks + list(self.BlockSubmissions)):
			if not ('name' in a and 'uri' in a):
				continue
			URI2Name.setdefault(a['uri'], a['name'])
			Name2URI.setdefault(a['name'], a['uri'])
		def URINamePair(a, defname):
			if 'name' not in a:
				a['name'] = URI2Name.get(a['uri'], defname)
			elif 'uri' not in a:
				a['uri'] = Name2URI[a['name']]
		_URI2Access = {}
		def URI2Access(uri):
			if uri not in _URI2Access:
				access = jsonrpc.ServiceProxy(uri)
				access.OldGMP = False
				_URI2Access[uri] = access
			return _URI2Access[uri]
		LeveledTS = {}
		for i in range(len(self.TemplateSources)):
			TS = self.TemplateSources[i]
			URINamePair(TS, 'TemplateSources[%u]' % (i,))
			TS.setdefault('priority', 0)
			TS.setdefault('weight', 1)
			TS['access'] = URI2Access(TS['uri'])
			LeveledTS.setdefault(TS['priority'], []).append(TS)
		LeveledTS = tuple(x[1] for x in sorted(LeveledTS.items()))
		self.TemplateSources = LeveledTS
		for i in range(len(self.TemplateChecks)):
			TC = self.TemplateChecks[i]
			URINamePair(TC, 'TemplateChecks[%u]' % (i,))
			TC.setdefault('unanimous', False)
			TC.setdefault('weight', 1)
			TC['access'] = URI2Access(TC['uri'])
		for i in range(len(getattr(self, 'BlockSubmissions', ()))):
			BS = self.BlockSubmissions[i]
			URINamePair(BS, 'BlockSubmissions[%u]' % (i,))
			BS['access'] = URI2Access(BS['uri'])
		
		self.ready = False
		self.readyCV = threading.Condition()
		
		self.currentMerkleTree = None
		self.merkleRoots = deque(maxlen=self.WorkQueueSizeRegular[1])
		self.LowestMerkleRoots = self.WorkQueueSizeRegular[1]
		
		if not hasattr(self, 'WorkQueueSizeClear'):
			self.WorkQueueSizeClear = self.WorkQueueSizeLongpoll
		self._MaxClearSize = max(self.WorkQueueSizeClear[1], self.WorkQueueSizeLongpoll[1])
		self.clearMerkleRoots = Queue(self._MaxClearSize)
		self.LowestClearMerkleRoots = self.WorkQueueSizeClear[1]
		self.nextMerkleRoots = Queue(self._MaxClearSize)
		
		if not hasattr(self, 'WarningDelay'):
			self.WarningDelay = max(15, self.MinimumTxnUpdateWait * 2)
		if not hasattr(self, 'WarningDelayTxnLongpoll'):
			self.WarningDelayTxnLongpoll = self.WarningDelay
		if not hasattr(self, 'WarningDelayMerkleUpdate'):
			self.WarningDelayMerkleUpdate = self.WarningDelay
		
		self.lastMerkleUpdate = 0
		self.nextMerkleUpdate = 0
	
	def createClearMerkleTree(self, height):
		subsidy = self.SubsidyAlgo(height)
		cbtxn = self.makeCoinbaseTxn(subsidy, False)
		cbtxn.assemble()
		return MerkleTree([cbtxn])
	
	def updateBlock(self, newBlock, height = None, bits = None, _HBH = None):
		if newBlock == self.currentBlock[0]:
			if height in (None, self.currentBlock[1]) and bits in (None, self.currentBlock[2]):
				return
			if not self.currentBlock[2] is None:
				self.logger.error('Was working on block with wrong specs: %s (height: %d->%d; bits: %s->%s' % (
					b2a_hex(newBlock[::-1]).decode('utf8'),
					self.currentBlock[1],
					height,
					b2a_hex(self.currentBlock[2][::-1]).decode('utf8'),
					b2a_hex(bits[::-1]).decode('utf8'),
				))
				if self.needMerkle == 1:
					self.needMerkle = False
				self.onBlockUpdate()
		
		# Old block is invalid
		if self.currentBlock[0] != newBlock:
			self.lastBlock = self.currentBlock
		
		lastHeight = self.currentBlock[1]
		if height is None:
			height = self.currentBlock[1] + 1
		if bits is None:
			if height % self.DifficultyChangeMod == 1 or self.currentBlock[2] is None:
				self.logger.warning('New block: %s (height %d; bits: UNKNOWN)' % (b2a_hex(newBlock[::-1]).decode('utf8'), height))
				# Pretend to be 1 lower height, so we possibly retain nextMerkleRoots
				self.currentBlock = (None, height - 1, None)
				OCMR = self.clearMerkleRoots
				self.clearMerkleRoots = Queue(self.WorkQueueSizeClear[1])
				if OCMR.empty():
					OCMR.put(None)
				self.merkleRoots.clear()
				self.ready = False
				return
			else:
				bits = self.currentBlock[2]
		
		if _HBH is None:
			_HBH = (b2a_hex(newBlock[::-1]).decode('utf8'), b2a_hex(bits[::-1]).decode('utf8'))
		self.logger.info('New block: %s (height: %d; bits: %s)' % (_HBH[0], height, _HBH[1]))
		self.currentBlock = (newBlock, height, bits)
		
		if lastHeight != height:
			# TODO: Perhaps reuse clear merkle trees more intelligently
			OCMR = self.clearMerkleRoots
			if lastHeight == height - 1:
				self.curClearMerkleTree = self.nextMerkleTree
				self.clearMerkleRoots = self.nextMerkleRoots
				self.logger.debug('Adopting next-height clear merkleroots :)')
			else:
				if lastHeight:
					self.logger.warning('Change from height %d->%d; no longpoll merkleroots available!' % (lastHeight, height))
				self.curClearMerkleTree = self.createClearMerkleTree(height)
				self.clearMerkleRoots = Queue(self.WorkQueueSizeClear[1])
			if OCMR.empty():
				OCMR.put(None)
			self.nextMerkleTree = self.createClearMerkleTree(height + 1)
			self.nextMerkleRoots = Queue(self._MaxClearSize)
		else:
			self.logger.debug('Already using clear merkleroots for this height')
		self.currentMerkleTree = self.curClearMerkleTree
		self.merkleRoots.clear()
		
		if not self.ready:
			self.ready = True
			with self.readyCV:
				self.readyCV.notify_all()
		
		self.needMerkle = 2
		self.onBlockChange()
	
	def _trimBlock(self, MP, txnlist, txninfo, floodn, msgf):
		fee = txninfo[-1].get('fee', None)
		if fee is None:
			raise self._floodCritical(now, floodn, doin=msgf('fees unknown'))
		if fee:
			# FIXME: coinbasevalue is *not* guaranteed to exist here
			MP['coinbasevalue'] -= fee
		
		txnlist[-1:] = ()
		txninfo[-1:] = ()
		
		return True
	
	# Aggressive "Power Of Two": Remove transactions even with fees to reach our goal
	def _APOT(self, txninfopot, MP, POTInfo):
		feeTxnsTrimmed = 0
		feesTrimmed = 0
		for txn in txninfopot:
			if txn.get('fee') is None:
				self._floodWarning(now, 'APOT-No-Fees', doin='Upstream didn\'t provide fee information required for aggressive POT', logf=self.logger.info)
				return
			if not txn['fee']:
				continue
			feesTrimmed += txn['fee']
			feeTxnsTrimmed += 1
		MP['coinbasevalue'] -= feesTrimmed
		
		POTInfo[2] = [feeTxnsTrimmed, feesTrimmed]
		self._floodWarning(now, 'POT-Trimming-Fees', doin='Aggressive POT trimming %d transactions with %d.%08d BTC total fees' % (feeTxnsTrimmed, feesTrimmed//100000000, feesTrimmed % 100000000), logf=self.logger.debug)
		
		return True
	
	def _makeBlockSafe(self, MP, txnlist, txninfo):
		blocksize = sum(map(len, txnlist)) + 80
		while blocksize > 934464:  # 1 "MB" limit - 64 KB breathing room
			txnsize = len(txnlist[-1])
			self._trimBlock(MP, txnlist, txninfo, 'SizeLimit', lambda x: 'Making blocks over 1 MB size limit (%d bytes; %s)' % (blocksize, x))
			blocksize -= txnsize
		
		# NOTE: This check doesn't work at all without BIP22 transaction obj format
		blocksigops = sum(a.get('sigops', 0) for a in txninfo)
		while blocksigops > 19488:  # 20k limit - 0x200 breathing room
			txnsigops = txninfo[-1]['sigops']
			self._trimBlock(MP, txnlist, txninfo, 'SigOpLimit', lambda x: 'Making blocks over 20k SigOp limit (%d; %s)' % (blocksigops, x))
			blocksigops -= txnsigops
		
		# Aim to produce blocks with "Power Of Two" transaction counts
		# This helps avoid any chance of someone abusing CVE-2012-2459 with them
		POTMode = getattr(self, 'POT', 1)
		txncount = len(txnlist) + 1
		if POTMode:
			feetxncount = txncount
			for i in range(txncount - 2, -1, -1):
				if 'fee' not in txninfo[i] or txninfo[i]['fee']:
					break
				feetxncount -= 1
			
			if getattr(self, 'Greedy', None):
				# Aim to cut off extra zero-fee transactions on the end
				# NOTE: not cutting out ones intermixed, in case of dependencies
				idealtxncount = feetxncount
			else:
				idealtxncount = txncount
			
			pot = 2**int(log(idealtxncount, 2))
			POTInfo = MP['POTInfo'] = [[idealtxncount, feetxncount, txncount], [pot, None], None]
			if pot < idealtxncount:
				if pot * 2 <= txncount:
					pot *= 2
				elif pot >= feetxncount:
					pass
				elif POTMode > 1:
					if self._APOT(txninfo[pot-1:], MP, POTInfo):
						# Trimmed even transactions with fees
						pass
					else:
						pot = idealtxncount
						self._floodWarning(now, 'Non-POT', doin='Making merkle tree with %d transactions (ideal: %d; max: %d)' % (pot, idealtxncount, txncount))
				else:
					pot = idealtxncount
			POTInfo[1][1] = pot
			pot -= 1
			txnlist[pot:] = ()
			txninfo[pot:] = ()
	
	def _CallGBT(self, TS):
		access = TS['access']
		self.logger.debug('Requesting new template from \'%s\'' % (TS['name'],))
		try:
			# First, try BIP 22 standard getblocktemplate :)
			MP = access.getblocktemplate(self.GBTReq)
			access.OldGMP = False
		except:
			try:
				# Failing that, give BIP 22 draft (2012-02 through 2012-07) getmemorypool a chance
				MP = access.getmemorypool(self.GMPReq)
			except:
				try:
					# Finally, fall back to bitcoind 0.5/0.6 getmemorypool
					MP = access.getmemorypool()
				except:
					MP = False
			if MP is False:
				# This way, we get the error from the BIP22 call if the old one fails too
				raise
			
			# Pre-BIP22 server (bitcoind <0.7 or Eloipool <20120513)
			if not access.OldGMP:
				access.OldGMP = True
				self.logger.warning('Upstream \'%s\' is not BIP 22 compatible' % (TS['name'],))
		
		return MP
	
	def _ProcessGBT(self, MP, TS = None):
		oMP = MP
		MP = deepcopy(MP)
		
		prevBlock = bytes.fromhex(MP['previousblockhash'])[::-1]
		if 'height' not in MP:
			MP['height'] = TS['access'].getinfo()['blocks'] + 1
		height = MP['height']
		bits = bytes.fromhex(MP['bits'])[::-1]
		(MP['_bits'], MP['_prevBlock']) = (bits, prevBlock)
		if (prevBlock, height, bits) != self.currentBlock and (self.currentBlock[1] is None or height > self.currentBlock[1]):
			self.updateBlock(prevBlock, height, bits, _HBH=(MP['previousblockhash'], MP['bits']))
		
		txnlist = MP['transactions']
		if len(txnlist) and isinstance(txnlist[0], dict):
			txninfo = txnlist
			txnlist = tuple(a['data'] for a in txnlist)
		elif 'transactionfees' in MP:
			# Backward compatibility with pre-BIP22 gmp_fees branch
			txninfo = [{'fee':a} for a in MP['transactionfees']]
		else:
			# Backward compatibility with pre-BIP22 hex-only (bitcoind <0.7, Eloipool <future)
			txninfo = [{}] * len(txnlist)
		# TODO: cache Txn or at least txid from previous merkle roots?
		txnlist = [a for a in map(bytes.fromhex, txnlist)]
		
		self._makeBlockSafe(MP, txnlist, txninfo)
		
		cbtxn = self.makeCoinbaseTxn(MP['coinbasevalue'], prevBlockHex = MP['previousblockhash'])
		cbtxn.setCoinbase(b'\0\0')
		cbtxn.assemble()
		txnlist.insert(0, cbtxn.data)
		txninfo.insert(0, {
		})
		
		txnlist = [a for a in map(Txn, txnlist[1:])]
		txnlist.insert(0, cbtxn)
		txnlist = list(txnlist)
		newMerkleTree = MerkleTree(txnlist)
		newMerkleTree.POTInfo = MP.get('POTInfo')
		newMerkleTree.MP = MP
		newMerkleTree.oMP = oMP
		
		return newMerkleTree
	
	def _CheckTemplate(self, newMerkleTree, TS):
		if not self.UseTemplateChecks:
			return (None, None)
		TCList = self.TemplateChecks
		if not TCList:
			if 'proposal' not in newMerkleTree.oMP.get('capabilities', ()):
				return (None, None)
			TCList = (
				{
					'name': TS['name'],
					'access': TS['access'],
					'unanimous': True,
					'weight': 1,
				},
			)
		
		MP = newMerkleTree.MP
		(prevBlock, height, bits) = (MP['_prevBlock'], MP['height'], MP['_bits'])
		txnlist = newMerkleTree.data
		cbtxn = txnlist[0]
		
		coinbase = self.makeCoinbase(height=height)
		cbtxn.setCoinbase(coinbase)
		cbtxn.assemble()
		merkleRoot = newMerkleTree.merkleRoot()
		MRD = (merkleRoot, newMerkleTree, coinbase, prevBlock, bits)
		blkhdr = MakeBlockHeader(MRD, self.BlockVersionBytes)
		data = assembleBlock(blkhdr, txnlist)
		ProposeReq = {
			"mode": "proposal",
			"data": b2a_hex(data).decode('utf8'),
		}
		
		AcceptedScore = 0
		RejectedScore = 0
		Rejections = {}
		ProposalErrors = {}
		for TC in TCList:
			caccess = TC['access']
			try:
				propose = caccess.getblocktemplate(ProposeReq)
			except (socket.error, ValueError) as e:
				self.logger.error('Upstream \'%s\' errored on proposal from \'%s\': %s' % (TC['name'], TS['name'], e))
				ProposalErrors[TC['name']] = e
				continue
			if propose is None:
				AcceptedScore += TC['weight']
				self.logger.debug('Upstream \'%s\' accepted proposal' % (TC['name'],))
			elif propose == 'orphan':
				self.logger.debug('Upstream \'%s\' considered proposal an orphan' % (TC['name'],))
				ProposalErrors[TC['name']] = propose
			else:
				RejectedScore += TC['weight']
				Rejections[TC['name']] = propose
				try:
					propose = propose['reject-reason']
				except:
					pass
				self.logger.error('Upstream \'%s\' rejected proposed block from \'%s\': %s' % (TC['name'], TS['name'], propose))
		
		if Rejections:
			RPInfo = {
				'merkleTree': newMerkleTree,
				'AcceptedScore': AcceptedScore,
				'RejectedScore': RejectedScore,
				'Rejections': Rejections,
				'ProposalErrors': ProposalErrors,
			}
			self.RejectedProposal = RPInfo
			
			try:
				global _filecounter
				_filecounter += 1
				import pickle
				with open('RejectedProposals/%d_%d' % (int(time()), _filecounter), 'wb') as f:
					pickle.dump(RPInfo, f)
			except IOError:
				pass
		
		TotalScore = AcceptedScore + RejectedScore
		
		return (AcceptedScore, TotalScore)
	
	def _updateMerkleTree_fromTS(self, TS):
		MP = self._CallGBT(TS)
		newMerkleTree = self._ProcessGBT(MP, TS)
		
		# Some versions of bitcoinrpc ServiceProxy have problems copying/pickling, so just store name and URI for now
		newMerkleTree.source = TS['name']
		newMerkleTree.source_uri = TS['uri']
		
		(AcceptedScore, TotalScore) = self._CheckTemplate(newMerkleTree, TS)
		if TotalScore is None:
			return (0, newMerkleTree)
		
		if TotalScore:
			AcceptRatio = AcceptedScore / TotalScore
		else:
			AcceptRatio = 0.0
		
		self.logger.debug('Template from \'%s\' has %s acceptance ratio and score of %s' % (TS['name'], AcceptRatio, AcceptedScore))
		
		if AcceptRatio <= self.MinimumTemplateAcceptanceRatio:
			return None
		
		if TotalScore < self.MinimumTemplateScore:
			return None
		
		return (AcceptRatio, newMerkleTree)
	
	def _updateMerkleTree_I(self):
		Best = (-1, None)
		for TSPriList in self.TemplateSources:
			# FIXME: Implement weighting
			for i in range(len(TSPriList)):
				TS = TSPriList.pop(0)
				TSPriList.append(TS)
				
				try:
					r = self._updateMerkleTree_fromTS(TS)
					if r is None:
						# Failed completely
						continue
					
					(AcceptRatio, newMerkleTree) = r
					
					# NOTE: If you're going to try to remove this preference for the highest block, you need to (at least) stop _ProcessGBT from calling updateBlock whenever it sees a new high
					AcceptRatio += newMerkleTree.MP['height']
					
					self.logger.debug('Template from \'%s\' has %s acceptance ratio at height %s' % (TS['name'], AcceptRatio, newMerkleTree.MP['height']))
					if Best[0] < AcceptRatio:
						Best = (AcceptRatio, newMerkleTree)
						if AcceptRatio == 1:
							break
				except:
					if TSPriList == self.TemplateSources[-1] and i == len(TSPriList) - 1 and Best[1] is None:
						raise
					else:
						self.logger.error(traceback.format_exc())
		
		BestMT = Best[1]
		if BestMT is None:
			raise RuntimeError('Failed to create usable template')
		
		self.logger.debug('Updating merkle tree with template from \'%s\'' % (BestMT.source,))
		MP = BestMT.MP
		blkbasics = (MP['_prevBlock'], MP['height'], MP['_bits'])
		if blkbasics != self.currentBlock:
			self.updateBlock(*blkbasics, _HBH=(MP['previousblockhash'], MP['bits']))
		self.currentMerkleTree = BestMT
	
	def _updateMerkleTree(self):
		global now
		self.logger.debug('Polling for new block template')
		self.nextMerkleUpdate = now + self.TxnUpdateRetryWait
		
		self._updateMerkleTree_I()
		
		self.lastMerkleUpdate = now
		self.nextMerkleUpdate = now + self.MinimumTxnUpdateWait
		
		if self.needMerkle == 2:
			self.needMerkle = 1
			self.needMerkleSince = now
	
	def updateMerkleTree(self):
		global now
		now = time()
		self._updateMerkleTree()
	
	def makeCoinbase(self, height):
		now = int(time())
		if now > _makeCoinbase[0]:
			_makeCoinbase[0] = now
			_makeCoinbase[1] = 0
		else:
			_makeCoinbase[1] += 1
		rv = self.CoinbasePrefix
		rv += pack('>L', now) + pack('>Q', _makeCoinbase[1]).lstrip(b'\0')
		# NOTE: Not using varlenEncode, since this is always guaranteed to be < 100
		rv = bytes( (len(rv),) ) + rv
		for v in self.CoinbaseAux.values():
			rv += v
		if len(rv) > 95:
			t = time()
			if self.overflowed < t - 300:
				self.logger.warning('Overflowing coinbase data! %d bytes long' % (len(rv),))
				self.overflowed = t
				self.isOverflowed = True
			rv = rv[:95]
		else:
			self.isOverflowed = False
		rv = bitcoin.script.encodeUNum(height) + rv
		return rv
	
	def makeMerkleRoot(self, merkleTree, height):
		cbtxn = merkleTree.data[0]
		cb = self.makeCoinbase(height=height)
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
	
	def _floodWarning(self, now, wid, wmsgf = None, doin = True, logf = None):
		if doin is True:
			doin = self._doing_last
			def a(f = wmsgf):
				return lambda: "%s (doing %s)" % (f(), doin)
			wmsgf = a()
		winfo = self.lastWarning.setdefault(wid, [0, None])
		(lastTime, lastDoing) = winfo
		if now <= lastTime + max(5, self.MinimumTxnUpdateWait):
			return
		winfo[0] = now
		nowDoing = doin
		winfo[1] = nowDoing
		if logf is None:
			logf = self.logger.warning
		logf(wmsgf() if wmsgf else doin)
	
	def _makeOne(self, putf, merkleTree, height):
		MakingAtThisHeight = self.currentBlock[1]
		MR = self.makeMerkleRoot(merkleTree, height=height)
		# Only add it if the height hasn't changed in the meantime, to avoid a race
		if self.currentBlock[1] == MakingAtThisHeight:
			putf(MR)
	
	def makeClear(self):
		self._doing('clear merkle roots')
		self._makeOne(self.clearMerkleRoots.put, self.curClearMerkleTree, height=self.currentBlock[1])
	
	def makeNext(self):
		self._doing('longpoll merkle roots')
		self._makeOne(self.nextMerkleRoots.put, self.nextMerkleTree, height=self.currentBlock[1] + 1)
	
	def makeRegular(self):
		self._doing('regular merkle roots')
		self._makeOne(self.merkleRoots.append, self.currentMerkleTree, height=self.currentBlock[1])
	
	def merkleMaker_II(self):
		global now
		
		# No bits = no mining :(
		if not self.ready:
			return self._updateMerkleTree()
		
		# First, ensure we have the minimum clear, next, and regular (in that order)
		if self.clearMerkleRoots.qsize() < self.WorkQueueSizeClear[0]:
			return self.makeClear()
		if self.nextMerkleRoots.qsize() < self.WorkQueueSizeLongpoll[0]:
			return self.makeNext()
		if len(self.merkleRoots) < self.WorkQueueSizeRegular[0]:
			return self.makeRegular()
		
		# If we've met the minimum requirements, consider updating the merkle tree
		if self.nextMerkleUpdate <= now:
			return self._updateMerkleTree()
		
		# Finally, fill up clear, next, and regular until we've met the maximums
		if self.clearMerkleRoots.qsize() < self.WorkQueueSizeClear[1]:
			return self.makeClear()
		if self.nextMerkleRoots.qsize() < self.WorkQueueSizeLongpoll[1]:
			return self.makeNext()
		if len(self.merkleRoots) < self.WorkQueueSizeRegular[1] or self.merkleRoots[0][1] != self.currentMerkleTree:
			return self.makeRegular()
		
		# Nothing left to do, fire onBlockUpdate event (if appropriate) and sleep
		if self.needMerkle == 1:
			self.onBlockUpdate()
			self.needMerkle = False
		self._doing('idle')
		# TODO: rather than sleepspin, block until MinimumTxnUpdateWait expires or threading.Condition(?)
		sleep(self.IdleSleepTime)
	
	def merkleMaker_I(self):
		global now
		now = time()
		
		self.merkleMaker_II()
		
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
		try:
			MRD = self.merkleRoots.pop()
			self.LowestMerkleRoots = min(len(self.merkleRoots), self.LowestMerkleRoots)
			rollPrevBlk = False
		except IndexError:
			qsz = self.clearMerkleRoots.qsize()
			if qsz < 0x10:
				self.logger.warning('clearMerkleRoots running out! only %d left' % (qsz,))
			MRD = None
			while MRD is None:
				MRD = self.clearMerkleRoots.get()
			self.LowestClearMerkleRoots = min(self.clearMerkleRoots.qsize(), self.LowestClearMerkleRoots)
			rollPrevBlk = True
		(merkleRoot, merkleTree, cb) = MRD
		(prevBlock, height, bits) = self.currentBlock
		return (merkleRoot, merkleTree, cb, prevBlock, bits, rollPrevBlk)
	
	def getMC(self, wantClear = False):
		if not self.ready:
			with self.readyCV:
				while not self.ready:
					self.readyCV.wait()
		(prevBlock, height, bits) = self.currentBlock
		mt = self.curClearMerkleTree if wantClear else self.currentMerkleTree
		cb = self.makeCoinbase(height=height)
		rollPrevBlk = (mt == self.curClearMerkleTree)
		return (height, mt, cb, prevBlock, bits, rollPrevBlk)

# merkleMaker tests
def _test():
	global now
	now = 1337039788
	MM = merkleMaker()
	reallogger = MM.logger
	class fakelogger:
		LO = False
		def critical(self, *a):
			if self.LO > 1: return
			reallogger.critical(*a)
		def warning(self, *a):
			if self.LO: return
			reallogger.warning(*a)
		def debug(self, *a):
			pass
	MM.logger = fakelogger()
	class NMTClass:
		pass
	
	# _makeBlockSafe tests
	from copy import deepcopy
	MP = {
		'coinbasevalue':50,
	}
	txnlist = [b'\0', b'\x01', b'\x02']
	txninfo = [{'fee':0, 'sigops':1}, {'fee':5, 'sigops':10000}, {'fee':0, 'sigops':10001}]
	def MBS(LO = 0):
		m = deepcopy( (MP, txnlist, txninfo) )
		MM.logger.LO = LO
		try:
			MM._makeBlockSafe(*m)
		except:
			if LO < 2:
				raise
		else:
			assert LO < 2  # An expected error wasn't thrown
		if 'POTInfo' in m[0]:
			del m[0]['POTInfo']
		return m
	MM.POT = 0
	assert MBS() == (MP, txnlist[:2], txninfo[:2])
	txninfo[2]['fee'] = 1
	MPx = deepcopy(MP)
	MPx['coinbasevalue'] -= 1
	assert MBS() == (MPx, txnlist[:2], txninfo[:2])
	txninfo[2]['sigops'] = 1
	assert MBS(1) == (MP, txnlist, txninfo)
	# APOT tests
	MM.POT = 2
	txnlist.append(b'\x03')
	txninfo.append({'fee':1, 'sigops':0})
	MPx = deepcopy(MP)
	MPx['coinbasevalue'] -= 1
	assert MBS() == (MPx, txnlist[:3], txninfo[:3])
	# POT tests
	MM.POT = 1
	MM.Greedy = True
	txninfo[1]['fee'] = 0
	txninfo[2]['fee'] = 0
	assert MBS(1) == (MP, txnlist, txninfo)
	# _ProcessGBT tests
	def makeCoinbaseTxn(coinbaseValue, useCoinbaser = True, prevBlockHex = None):
		txn = Txn.new()
		txn.addOutput(coinbaseValue, b'')
		return txn
	MM.makeCoinbaseTxn = makeCoinbaseTxn
	MM.updateBlock = lambda *a, **ka: None
	gbt = {
		'transactions': [
			{'data': '11', 'depends': [], 'fee': 1, 'sigops': 1},
			{'data': '11', 'depends': [], 'fee': 0, 'sigops': 1},
			{'data': '11', 'depends': [], 'fee': 0, 'sigops': 1},
			{'data': '11', 'depends': [], 'fee': 1, 'sigops': 2}
		],
		'height': 219507,
		'coinbasevalue': 3,
		'previousblockhash': '000000000000012806bc100006dc83220bd9c2ac2709dc14a0d0fa1d6f9b733c',
		'version': 1,
		'bits': '1a05a6b1'
	}
	nMT = MM._ProcessGBT(gbt)
	assert len(nMT.data) == 5
	nMT.data[0].disassemble()
	assert sum(outp[0] for outp in nMT.data[0].outputs) == 3
	MM.POT = 2
	nMT = MM._ProcessGBT(gbt)
	assert len(nMT.data) in (2, 4)
	nMT.data[0].disassemble()
	assert sum(outp[0] for outp in nMT.data[0].outputs) == 2

_test()
