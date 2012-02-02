#!/usr/bin/python3
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

import config


import logging

logging.basicConfig(level=logging.DEBUG)
for infoOnly in ('checkShare', 'JSONRPCHandler', 'merkleMaker'):
	logging.getLogger(infoOnly).setLevel(logging.INFO)

def RaiseRedFlags(reason):
	logging.getLogger('redflag').critical(reason)
	return reason


from bitcoin.node import BitcoinLink
UpstreamBitcoind = BitcoinLink( config.UpstreamBitcoindNode, config.UpstreamNetworkId )

import jsonrpc
UpstreamBitcoindJSONRPC = jsonrpc.ServiceProxy(config.UpstreamURI)


from bitcoin.script import BitcoinScript
from bitcoin.txn import Txn
from base58 import b58decode
from struct import pack
import subprocess
from time import time

def makeCoinbaseTxn(coinbaseValue, useCoinbaser = True):
	t = Txn.new()
	
	if useCoinbaser and hasattr(config, 'CoinbaserCmd') and config.CoinbaserCmd:
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
MM.start()


from binascii import b2a_hex
from copy import deepcopy
from struct import pack, unpack
from time import time
from util import RejectedShare, dblsha, hash2int
import jsonrpc
import threading
import traceback

gotwork = None
if hasattr(config, 'GotWorkURI'):
	gotwork = jsonrpc.ServiceProxy(config.GotWorkURI)

def submitGotwork(info):
	try:
		gotwork.gotwork(info)
	except:
		checkShare.logger.warning('Failed to submit gotwork\n' + traceback.format_exc())

db = None
if hasattr(config, 'DbOptions'):
	import psycopg2
	db = psycopg2.connect(**config.DbOptions)

def getBlockHeader(username):
	MRD = MM.getMRD()
	(merkleRoot, merkleTree, coinbase, prevBlock, bits, rollPrevBlk) = MRD
	timestamp = pack('<L', int(time()))
	hdr = b'\1\0\0\0' + prevBlock + merkleRoot + timestamp + bits + b'iolE'
	workLog.setdefault(username, {})[merkleRoot] = (MRD, time())
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

RBDs = []
RBPs = []

from bitcoin.varlen import varlenEncode
def assembleBlock(blkhdr, txlist):
	payload = blkhdr
	payload += varlenEncode(len(txlist))
	for tx in txlist:
		payload += tx.data
	return payload

def blockSubmissionThread(payload):
	while True:
		try:
			UpstreamBitcoindJSONRPC.getmemorypool(b2a_hex(payload).decode('ascii'))
			break
		except:
			pass

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
	
	if data[72:76] != bits:
		raise RejectedShare('bad-diffbits')
	if data[:4] != b'\1\0\0\0':
		raise RejectedShare('bad-version')
	
	MWL = workLog[username]
	if shareMerkleRoot not in MWL:
		raise RejectedShare('unknown-work')
	(MRD, t) = MWL[shareMerkleRoot]
	share['MRD'] = MRD
	
	if data in DupeShareHACK:
		raise RejectedShare('duplicate')
	DupeShareHACK[data] = None
	
	shareTimestamp = unpack('<L', data[68:72])[0]
	shareTime = share['time'] = time()
	if shareTime < t - 120:
		raise RejectedShare('stale-work')
	if shareTimestamp < shareTime - 300:
		raise RejectedShare('time-too-old')
	if shareTimestamp > shareTime + 7200:
		raise RejectedShare('time-too-new')
	
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
		RBDs.append( deepcopy( (data, txlist) ) )
		payload = assembleBlock(data, txlist)
		logfunc('Real block payload: %s' % (payload,))
		RBPs.append(payload)
		threading.Thread(target=blockSubmissionThread, args=(payload,)).start()
		UpstreamBitcoind.submitBlock(payload)
		share['upstreamResult'] = True
		MM.updateBlock(blkhash)
	
	# Gotwork hack...
	if gotwork and blkhashn <= config.GotWorkTarget:
		try:
			coinbaseMrkl = t.data
			coinbaseMrkl += blkhash
			steps = MRD[1]._steps
			coinbaseMrkl += pack('B', len(steps))
			for step in steps:
				coinbaseMrkl += step
			coinbaseMrkl += b"\0\0\0\0"
			info = {}
			info['hash'] = b2a_hex(blkhash).decode('ascii')
			info['header'] = b2a_hex(data).decode('ascii')
			info['coinbaseMrkl'] = b2a_hex(coinbaseMrkl).decode('ascii')
			thr = threading.Thread(target=submitGotwork, args=(info,))
			thr.daemon = True
			thr.start()
		except:
			checkShare.logger.warning('Failed to build gotwork request')
	
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
	logging.getLogger('newBlockNotification').info('Received new block notification')
	MM.updateMerkleTree()
	# TODO: Force RESPOND TO LONGPOLLS?
	pass

from signal import signal, SIGUSR1
signal(SIGUSR1, newBlockNotification)


import os
import os.path
import pickle
import signal
import sys
from time import sleep
import traceback

SAVE_STATE_FILENAME = 'eloipool.worklog'

def exit():
	logger = logging.getLogger('exit')
	
	# First, shutdown servers...
	logger.info('Stopping servers...')
	global server
	server.keepgoing = False
	os.write(server._LPSock, b'\1')  # HACK
	i = 0
	while server.running:
		i += 1
		if i >= 0x100:
			logger.error('JSONRPCServer taking too long to stop, giving up')
			break
		sleep(0.01)
	
	# Then, save data needed to resume work
	logger.info('Saving work state...')
	i = 0
	while True:
		try:
			with open(SAVE_STATE_FILENAME, 'wb') as f:
				pickle.dump( (workLog, DupeShareHACK), f )
			break
		except:
			i += 1
			if i >= 0x10000:
				logger.error('Failed to save work\n' + traceback.format_exc())
				try:
					os.unlink(SAVE_STATE_FILENAME)
				except:
					logger.error(('Failed to unlink \'%s\'; resume may have trouble\n' % (SAVE_STATE_FILENAME,)) + traceback.format_exc())
	
	# Finally, exit for real via SIGTERM
	logger.info('Goodbye...')
	os.kill(os.getpid(), signal.SIGTERM)
	sys.exit(0)

def restoreState():
	if not os.path.exists(SAVE_STATE_FILENAME):
		return
	
	global workLog, DupeShareHACK
	
	logger = logging.getLogger('restoreState')
	logger.info('Restoring saved state from \'%s\'' % (SAVE_STATE_FILENAME,))
	try:
		with open(SAVE_STATE_FILENAME, 'rb') as f:
			data = pickle.load(f)
			workLog = data[0]
			DupeShareHACK = data[1]
	except:
		logger.error('Failed to restore state\n' + traceback.format_exc())
		return
	try:
		os.unlink(SAVE_STATE_FILENAME)
	except:
		logger.info(('Failed to unlink \'%s\' following restore\n' % (SAVE_STATE_FILENAME,)) + traceback.format_exc())
	logger.info('State restored successfully')

restoreState()


from jsonrpcserver import JSONRPCListener, JSONRPCServer
import interactivemode

if __name__ == "__main__":
	server = JSONRPCServer()
	if hasattr(config, 'JSONRPCAddress'):
		if not hasattr(config, 'JSONRPCAddresses'):
			config.JSONRPCAddresses = []
		config.JSONRPCAddresses.insert(0, config.JSONRPCAddress)
	LS = []
	for a in config.JSONRPCAddresses:
		LS.append(JSONRPCListener(server, a))
	if hasattr(config, 'SecretUser'):
		server.SecretUser = config.SecretUser
	server.aux = MM.CoinbaseAux
	server.getBlockHeader = getBlockHeader
	server.receiveShare = receiveShare
	server.RaiseRedFlags = RaiseRedFlags
	server.serve_forever()
