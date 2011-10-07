#!/usr/bin/python3
import config


def RaiseRedFlags(reason):
	# FIXME: Critical-log
	return reason


from bitcoinnode import BitcoinLink
UpstreamBitcoind = BitcoinLink( config.UpstreamBitcoindNode, config.UpstreamNetworkId )


from bitcointxn import Txn
def makeCoinbaseTxn(coinbaseValue):
	t = Txn.new()
	t.setCoinbase(b'HI')
	t.addOutput(coinbaseValue, b'\x76\xa9\x14' + b'\xa7\x0e\x0a\x44\x09\x56\xf1\x35\x85\x6e\x77\x9e\xd9\x24\x55\xa8\x13\xb3\x10\xf1' + b'\x88\xac')
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
	
	print('BLKHASH: %64x' % (blkhashn,))
	global networkTarget
	print(' TARGET: %64x' % (networkTarget,))
	
	if blkhashn <= networkTarget:
		print("Submitting upstream")
		MRD[1].data[0] = MRD[2]
		UpstreamBitcoind.submitBlock(data, MRD[1].data)

def receiveShare(share):
	print(share)
	# TODO: username => userid
	checkShare(share)
	# TODO

def newBlockNotification(signum, frame):
	MM.updateMerkleTree()
	# TODO: Force RESPOND TO LONGPOLLS?
	pass

from signal import signal, SIGUSR1
signal(SIGUSR1, newBlockNotification)


from jsonrpcServer import JSONRPCServer
import interactiveMode

if __name__ == "__main__":
	server = JSONRPCServer(('', 8444))
	server.getBlockHeader = getBlockHeader
	server.receiveShare = receiveShare
	server.RaiseRedFlags = RaiseRedFlags
	server.serve_forever()
