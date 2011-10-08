#!/usr/bin/python3
import config


import logging

logging.basicConfig(level=logging.DEBUG)

def RaiseRedFlags(reason):
	logging.getLogger('redflag').critical(reason)
	return reason


from bitcoin.node import BitcoinLink
UpstreamBitcoind = BitcoinLink( config.UpstreamBitcoindNode, config.UpstreamNetworkId )


from bitcoin.txn import Txn
from base58 import b58decode
from struct import pack
from time import time

def makeCoinbase():
	now = int(time())
	if now > makeCoinbase.last:
		makeCoinbase.last = now
		makeCoinbase.extranonce = 0
	else:
		makeCoinbase.extranonce += 1
	return pack('>L', now) + pack('>Q', makeCoinbase.extranonce).lstrip(b'\0')
makeCoinbase.last = 0

def makeCoinbaseTxn(coinbaseValue):
	t = Txn.new()
	t.setCoinbase(makeCoinbase())
	addr = config.TrackerAddr
	pubkeyhash = b58decode(addr, 25)[1:-4]
	t.addOutput(coinbaseValue, b'\x76\xa9\x14' + pubkeyhash + b'\x88\xac')
	t.assemble()
	# TODO
	# TODO: red flag on dupe coinbase
	return t


from util import Bits2Target

workLog = {}
networkTarget = None

def blockChanged():
	global MM, networkTarget
	networkTarget = Bits2Target(MM.currentBlock[1])
	workLog.clear()


from merklemaker import merkleMaker
MM = merkleMaker()
MM.__dict__.update(config.__dict__)
MM.makeCoinbaseTxn = makeCoinbaseTxn
MM.onBlockChange = blockChanged
MM._THISISUGLY = UpstreamBitcoind
MM.start()


from binascii import b2a_hex
from struct import pack, unpack
from time import time
from util import RejectedShare, dblsha, hash2int

def getBlockHeader(username):
	MRD = MM.getMRD()
	(merkleRoot, merkleTree, coinbaseTxn, prevBlock, bits, rollPrevBlk) = MRD
	timestamp = pack('<L', int(time()))
	hdr = b'\1\0\0\0' + prevBlock + merkleRoot + timestamp + bits + b'iolE'
	workLog.setdefault(username, {})[merkleRoot] = MRD
	return hdr

def checkShare(share):
	data = share['data']
	(prevBlock, bits) = MM.currentBlock
	sharePrevBlock = data[4:36]
	if sharePrevBlock != prevBlock:
		if sharePrevBlock == MM.lastBlock[0]:
			raise RejectedShare('stale-prevblk')
		raise RejectedShare('bad-prevblk')
	
	shareMerkleRoot = data[36:68]
	# TODO: use userid
	username = share['username']
	if username not in workLog:
		raise RejectedShare('unknown-user')
	MWL = workLog[username]
	if shareMerkleRoot not in MWL:
		raise RejectedShare('unknown-work')
	MRD = MWL[shareMerkleRoot]
	share['MRD'] = MRD
	
	shareTimestamp = unpack('<L', data[68:72])[0]
	shareTime = share['time'] = time()
	if shareTimestamp < shareTime - 300:
		raise RejectedShare('time-too-old')
	if shareTimestamp > shareTime + 7200:
		raise RejectedShare('time-too-new')
	if data[72:76] != bits:
		raise RejectedShare('bad-diffbits')
	if data[:4] != b'\1\0\0\0':
		raise RejectedShare('bad-version')
	
	blkhash = dblsha(data)
	if blkhash[28:] != b'\0\0\0\0':
		raise RejectedShare('H-not-zero')
	blkhashn = hash2int(blkhash)
	
	global networkTarget
	logfunc = getattr(checkShare.logger, 'info' if blkhashn <= networkTarget else 'debug')
	logfunc('BLKHASH: %64x' % (blkhashn,))
	logfunc(' TARGET: %64x' % (networkTarget,))
	
	if blkhashn <= networkTarget:
		logfunc("Submitting upstream")
		MRD[1].data[0] = MRD[2]
		UpstreamBitcoind.submitBlock(data, MRD[1].data)
checkShare.logger = logging.getLogger('checkShare')

def receiveShare(share):
	# TODO: username => userid
	checkShare(share)
	# TODO

def newBlockNotification(signum, frame):
	MM.updateMerkleTree()
	# TODO: Force RESPOND TO LONGPOLLS?
	pass

from signal import signal, SIGUSR1
signal(SIGUSR1, newBlockNotification)


from jsonrpcserver import JSONRPCServer
import interactivemode

if __name__ == "__main__":
	server = JSONRPCServer(('', 8444))
	server.getBlockHeader = getBlockHeader
	server.receiveShare = receiveShare
	server.RaiseRedFlags = RaiseRedFlags
	server.serve_forever()
