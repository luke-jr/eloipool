#!/usr/bin/python3
import config


import logging

logging.basicConfig(level=logging.DEBUG)

def RaiseRedFlags(reason):
	logging.getLogger('redflag').critical(reason)
	return reason


from bitcoin.node import BitcoinLink
UpstreamBitcoind = BitcoinLink( config.UpstreamBitcoindNode, config.UpstreamNetworkId )


from bitcoin.script import BitcoinScript
from bitcoin.txn import Txn
from base58 import b58decode
from struct import pack
import subprocess
from time import time

def makeCoinbaseTxn(coinbaseValue, useCoinbaser = True):
	t = Txn.new()
	
	if useCoinbaser and hasattr(config, 'CoinbaserCmd'):
		coinbased = 0
		try:
			cmd = config.CoinbaserCmd
			cmd = cmd.replace('%d', str(coinbaseValue))
			p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
			nout = int(p.stdout.readline())
			for i in range(nout):
				amount = int(p.stdout.readline())
				addr = p.stdout.readline().rstrip(b'\n').decode('utf8')
				pkScript = BitcoinScript.toAddress(addr)
				t.addOutput(amount, pkScript)
				coinbased += amount
		except:
			coinbased = coinbaseValue + 1
		if coinbased >= coinbaseValue:
			logging.getLogger('makeCoinbaseTxn').error('Coinbaser failed!')
			t.outputs = []
		else:
			coinbaseValue -= coinbased
	
	pkScript = BitcoinScript.toAddress(config.TrackerAddr)
	t.addOutput(coinbaseValue, pkScript)
	
	# TODO
	# TODO: red flag on dupe coinbase
	return t


from util import Bits2Target

workLog = {}
networkTarget = None
DupeShareHACK = {}

server = None
def updateBlocks():
	if server:
		server.wakeLongpoll()

def blockChanged():
	global DupeShareHACK
	DupeShareHACK = {}
	global MM, networkTarget, server
	networkTarget = Bits2Target(MM.currentBlock[1])
	workLog.clear()
	updateBlocks()


from merklemaker import merkleMaker
MM = merkleMaker()
MM.__dict__.update(config.__dict__)
MM.clearCoinbaseTxn = makeCoinbaseTxn(5000000000, False)  # FIXME
MM.clearCoinbaseTxn.assemble()
MM.makeCoinbaseTxn = makeCoinbaseTxn
MM.onBlockChange = blockChanged
MM.onBlockUpdate = updateBlocks
MM._THISISUGLY = UpstreamBitcoind
MM.start()


from binascii import b2a_hex
from struct import pack, unpack
from time import time
from util import RejectedShare, dblsha, hash2int
import jsonrpc

gotwork = None
if hasattr(config, 'GotWorkURI'):
	gotwork = jsonrpc.ServiceProxy(config.GotWorkURI)

db = None
if hasattr(config, 'DbOptions'):
	import psycopg2
	db = psycopg2.connect(**config.DbOptions)

def getBlockHeader(username):
	MRD = MM.getMRD()
	(merkleRoot, merkleTree, coinbase, prevBlock, bits, rollPrevBlk) = MRD
	timestamp = pack('<L', int(time()))
	hdr = b'\1\0\0\0' + prevBlock + merkleRoot + timestamp + bits + b'iolE'
	workLog.setdefault(username, {})[merkleRoot] = MRD
	return hdr

def YN(b):
	if b is None:
		return None
	return 'Y' if b else 'N'

def logShare(share):
	if db is None:
		return
	dbc = db.cursor()
	rem_host = share.get('remoteHost', '?')
	username = share['username']
	reason = share.get('rejectReason', None)
	upstreamResult = share.get('upstreamResult', None)
	solution = share['_origdata']
	#solution = b2a_hex(solution).decode('utf8')
	stmt = "insert into shares (rem_host, username, our_result, upstream_result, reason, solution) values (%s, %s, %s, %s, %s, decode(%s, 'hex'))"
	params = (rem_host, username, YN(not reason), YN(upstreamResult), reason, solution)
	dbc.execute(stmt, params)
	db.commit()

def checkShare(share):
	data = share['data']
	data = data[:80]
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
	
	if data in DupeShareHACK:
		raise RejectedShare('duplicate')
	DupeShareHACK[data] = None
	
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
	
	txlist = MRD[1].data
	t = txlist[0]
	t.setCoinbase(MRD[2])
	t.assemble()
	
	if blkhashn <= networkTarget:
		logfunc("Submitting upstream")
		UpstreamBitcoind.submitBlock(data, txlist)
		share['upstreamResult'] = True
		MM.updateBlock(blkhash)
	
	# Gotwork hack...
	if gotwork:
		try:
			coinbaseMrkl = t.data
			coinbaseMrkl += blkhash
			steps = MRD[1]._steps
			coinbaseMrkl += pack('B', len(steps) + 1)
			coinbaseMrkl += t.txid
			for step in steps:
				coinbaseMrkl += step
			coinbaseMrkl += b"\0\0\0\0"
			info = {}
			info['hash'] = b2a_hex(blkhash).decode('ascii')
			info['header'] = b2a_hex(data).decode('ascii')
			info['coinbaseMrkl'] = b2a_hex(coinbaseMrkl).decode('ascii')
			gotwork.gotwork(info)
		except:
			checkShare.logger.warning('Failed to submit gotwork')
	
	logShare(share)
checkShare.logger = logging.getLogger('checkShare')

def receiveShare(share):
	# TODO: username => userid
	try:
		checkShare(share)
	except RejectedShare as rej:
		share['rejectReason'] = str(rej)
		logShare(share)
		raise
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
	server = JSONRPCServer(config.JSONRPCAddress)
	if hasattr(config, 'SecretUser'):
		server.SecretUser = config.SecretUser
	server.aux = MM.CoinbaseAux
	server.getBlockHeader = getBlockHeader
	server.receiveShare = receiveShare
	server.RaiseRedFlags = RaiseRedFlags
	server.serve_forever()
