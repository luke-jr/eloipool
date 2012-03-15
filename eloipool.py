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

if len(logging.root.handlers) == 0:
	logging.basicConfig(
		format='%(asctime)s\t%(name)s\t%(levelname)s\t%(message)s',
		level=logging.DEBUG,
	)
	for infoOnly in ('checkShare', 'JSONRPCHandler', 'merkleMaker', 'Waker for JSONRPCServer', 'JSONRPCServer'):
		logging.getLogger(infoOnly).setLevel(logging.INFO)

def RaiseRedFlags(reason):
	logging.getLogger('redflag').critical(reason)
	return reason


from bitcoin.node import BitcoinLink, BitcoinNode
bcnode = BitcoinNode(config.UpstreamNetworkId)
bcnode.userAgent += b'Eloipool:0.1/'

import jsonrpc
UpstreamBitcoindJSONRPC = jsonrpc.ServiceProxy(config.UpstreamURI)


from bitcoin.script import BitcoinScript
from bitcoin.txn import Txn
from base58 import b58decode
from struct import pack
import subprocess
from time import time

def makeCoinbaseTxn(coinbaseValue, useCoinbaser = True):
	txn = Txn.new()
	
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
				txn.addOutput(amount, pkScript)
				coinbased += amount
		except:
			coinbased = coinbaseValue + 1
		if coinbased >= coinbaseValue:
			logging.getLogger('makeCoinbaseTxn').error('Coinbaser failed!')
			txn.outputs = []
		else:
			coinbaseValue -= coinbased
	
	pkScript = BitcoinScript.toAddress(config.TrackerAddr)
	txn.addOutput(coinbaseValue, pkScript)
	
	# TODO
	# TODO: red flag on dupe coinbase
	return txn


import jsonrpc_getwork
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
	jsonrpc_getwork._CheckForDupesHACK = {}
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
from util import RejectedShare, dblsha, hash2int, swap32
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

def getBlockHeader(username):
	MRD = MM.getMRD()
	(merkleRoot, merkleTree, coinbase, prevBlock, bits, rollPrevBlk) = MRD
	timestamp = pack('<L', int(time()))
	hdr = b'\1\0\0\0' + prevBlock + merkleRoot + timestamp + bits + b'iolE'
	workLog.setdefault(username, {})[merkleRoot] = (MRD, time())
	return (hdr, workLog[username][merkleRoot])

def getBlockTemplate(username):
	MC = MM.getMC()
	(dummy, merkleTree, coinbase, prevBlock, bits) = MC
	wliLen = coinbase[0]
	wli = coinbase[1:wliLen+1]
	workLog.setdefault(username, {})[wli] = (MC, time())
	return MC

loggersShare = []

RBDs = []
RBPs = []

from bitcoin.varlen import varlenEncode, varlenDecode
import bitcoin.txn
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
	shareTime = share['time'] = time()
	
	data = share['data']
	data = data[:80]
	(prevBlock, bits) = MM.currentBlock
	sharePrevBlock = data[4:36]
	if sharePrevBlock != prevBlock:
		if sharePrevBlock == MM.lastBlock[0]:
			raise RejectedShare('stale-prevblk')
		raise RejectedShare('bad-prevblk')
	
	# TODO: use userid
	username = share['username']
	if username not in workLog:
		raise RejectedShare('unknown-user')
	
	if data[72:76] != bits:
		raise RejectedShare('bad-diffbits')
	if data[:4] != b'\1\0\0\0':
		raise RejectedShare('bad-version')
	
	shareMerkleRoot = data[36:68]
	if 'blkdata' in share:
		pl = share['blkdata']
		(txncount, pl) = varlenDecode(pl)
		cbtxn = bitcoin.txn.Txn(pl)
		cbtxn.disassemble(retExtra=True)
		coinbase = cbtxn.getCoinbase()
		wliLen = coinbase[0]
		wli = coinbase[1:wliLen+1]
		mode = 'MC'
		moden = 1
	else:
		wli = shareMerkleRoot
		mode = 'MRD'
		moden = 0
	
	MWL = workLog[username]
	if wli not in MWL:
		raise RejectedShare('unknown-work')
	(wld, issueT) = MWL[wli]
	share[mode] = wld
	
	if data in DupeShareHACK:
		raise RejectedShare('duplicate')
	DupeShareHACK[data] = None
	
	blkhash = dblsha(data)
	if blkhash[28:] != b'\0\0\0\0':
		raise RejectedShare('H-not-zero')
	blkhashn = hash2int(blkhash)
	
	global networkTarget
	logfunc = getattr(checkShare.logger, 'info' if blkhashn <= networkTarget else 'debug')
	logfunc('BLKHASH: %64x' % (blkhashn,))
	logfunc(' TARGET: %64x' % (networkTarget,))
	
	workMerkleTree = wld[1]
	workCoinbase = wld[2]
	
	# NOTE: this isn't actually needed for MC mode, but we're abusing it for a trivial share check...
	txlist = workMerkleTree.data
	txlist = [deepcopy(txlist[0]),] + txlist[1:]
	cbtxn = txlist[0]
	cbtxn.setCoinbase(workCoinbase)
	cbtxn.assemble()
	
	if blkhashn <= networkTarget:
		logfunc("Submitting upstream")
		if not moden:
			RBDs.append( deepcopy( (data, txlist) ) )
			payload = assembleBlock(data, txlist)
		else:
			RBDs.append( deepcopy( (data, txlist, share['blkdata']) ) )
			payload = share['data'] + share['blkdata']
		logfunc('Real block payload: %s' % (payload,))
		RBPs.append(payload)
		threading.Thread(target=blockSubmissionThread, args=(payload,)).start()
		bcnode.submitBlock(payload)
		share['upstreamResult'] = True
		MM.updateBlock(blkhash)
	
	# Gotwork hack...
	if gotwork and blkhashn <= config.GotWorkTarget:
		try:
			coinbaseMrkl = cbtxn.data
			coinbaseMrkl += blkhash
			steps = workMerkleTree._steps
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
	
	shareTimestamp = unpack('<L', data[68:72])[0]
	if shareTime < issueT - 120:
		raise RejectedShare('stale-work')
	if shareTimestamp < shareTime - 300:
		raise RejectedShare('time-too-old')
	if shareTimestamp > shareTime + 7200:
		raise RejectedShare('time-too-new')
	
	if moden:
		cbpre = cbtxn.getCoinbase()
		cbpreLen = len(cbpre)
		if coinbase[:cbpreLen] != cbpre:
			raise RejectedShare('bad-cb-prefix')
		
		# Filter out known "I support" flags, to prevent exploits
		for ff in (b'/P2SH/', b'NOP2SH', b'p2sh/CHV', b'p2sh/NOCHV'):
			if coinbase.find(ff) > cbpreLen - len(ff):
				raise RejectedShare('bad-cb-flag')
		
		if len(coinbase) > 100:
			raise RejectedShare('bad-cb-length')
		
		cbtxn.setCoinbase(coinbase)
		cbtxn.assemble()
		if shareMerkleRoot != workMerkleTree.withFirst(cbtxn):
			raise RejectedShare('bad-txnmrklroot')
		
		allowed = assembleBlock(data, txlist)
		if allowed != share['data'] + share['blkdata']:
			raise RejectedShare('bad-txns')
checkShare.logger = logging.getLogger('checkShare')

def receiveShare(share):
	# TODO: username => userid
	try:
		checkShare(share)
	except RejectedShare as rej:
		share['rejectReason'] = str(rej)
		raise
	finally:
		if '_origdata' in share:
			share['solution'] = share['_origdata']
		else:
			share['solution'] = b2a_hex(swap32(share['data'])).decode('utf8')
		for i in loggersShare:
			i(share)

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

def stopServers():
	logger = logging.getLogger('stopServers')
	
	logger.info('Stopping servers...')
	global bcnode, server
	servers = (bcnode, server)
	for s in servers:
		s.keepgoing = False
	for s in servers:
		s.wakeup()
	i = 0
	while True:
		sl = []
		for s in servers:
			if s.running:
				sl.append(s.__class__.__name__)
		if not sl:
			break
		i += 1
		if i >= 0x100:
			logger.error('Servers taking too long to stop (%s), giving up' % (', '.join(sl)))
			break
		sleep(0.01)
	
	for s in servers:
		for fd in s._fd.keys():
			os.close(fd)

def saveState(t = None):
	logger = logging.getLogger('saveState')
	
	# Then, save data needed to resume work
	logger.info('Saving work state to \'%s\'...' % (SAVE_STATE_FILENAME,))
	i = 0
	while True:
		try:
			with open(SAVE_STATE_FILENAME, 'wb') as f:
				pickle.dump(t, f)
				pickle.dump(DupeShareHACK, f)
				pickle.dump(workLog, f)
			break
		except:
			i += 1
			if i >= 0x10000:
				logger.error('Failed to save work\n' + traceback.format_exc())
				try:
					os.unlink(SAVE_STATE_FILENAME)
				except:
					logger.error(('Failed to unlink \'%s\'; resume may have trouble\n' % (SAVE_STATE_FILENAME,)) + traceback.format_exc())

def exit():
	t = time()
	stopServers()
	saveState(t)
	logging.getLogger('exit').info('Goodbye...')
	os.kill(os.getpid(), signal.SIGTERM)
	sys.exit(0)

def restart():
	t = time()
	stopServers()
	saveState(t)
	logging.getLogger('restart').info('Restarting...')
	try:
		os.execv(sys.argv[0], sys.argv)
	except:
		logging.getLogger('restart').error('Failed to exec\n' + traceback.format_exc())

def restoreState():
	if not os.path.exists(SAVE_STATE_FILENAME):
		return
	
	global workLog, DupeShareHACK
	
	logger = logging.getLogger('restoreState')
	s = os.stat(SAVE_STATE_FILENAME)
	logger.info('Restoring saved state from \'%s\' (%d bytes)' % (SAVE_STATE_FILENAME, s.st_size))
	try:
		with open(SAVE_STATE_FILENAME, 'rb') as f:
			t = pickle.load(f)
			if type(t) == tuple:
				workLog = t[0]
				DupeShareHACK = t[1]
				t = None
			else:
				if isinstance(t, dict):
					DupeShareHACK = t
					t = None
				else:
					DupeShareHACK = pickle.load(f)
				
				if s.st_mtime + 120 >= time():
					workLog = pickle.load(f)
				else:
					logger.debug('Skipping restore of expired workLog')
	except:
		logger.error('Failed to restore state\n' + traceback.format_exc())
		return
	logger.info('State restored successfully')
	if t:
		logger.info('Total downtime: %g seconds' % (time() - t,))


from jsonrpcserver import JSONRPCListener, JSONRPCServer
import interactivemode
from networkserver import NetworkListener
import threading
import sharelogging
import imp

if __name__ == "__main__":
	if not hasattr(config, 'ShareLogging'):
		config.ShareLogging = ()
	if hasattr(config, 'DbOptions'):
		logging.getLogger('backwardCompatibility').warn('DbOptions configuration variable is deprecated; upgrade to ShareLogging var before 2013-03-05')
		config.ShareLogging = list(config.ShareLogging)
		config.ShareLogging.append( {
			'type': 'sql',
			'engine': 'postgres',
			'dbopts': config.DbOptions,
			'statement': "insert into shares (rem_host, username, our_result, upstream_result, reason, solution) values ({Q(remoteHost)}, {username}, {YN(not(rejectReason))}, {YN(upstreamResult)}, {rejectReason}, decode({solution}, 'hex'))",
		} )
	for i in config.ShareLogging:
		if not hasattr(i, 'keys'):
			name, parameters = i
			logging.getLogger('backwardCompatibility').warn('Using short-term backward compatibility for ShareLogging[\'%s\']; be sure to update config before 2012-04-04' % (name,))
			if name == 'postgres':
				name = 'sql'
				i = {
					'engine': 'postgres',
					'dbopts': parameters,
				}
			elif name == 'logfile':
				i = {}
				i['thropts'] = parameters
				if 'filename' in parameters:
					i['filename'] = parameters['filename']
					i['thropts'] = dict(i['thropts'])
					del i['thropts']['filename']
			else:
				i = parameters
			i['type'] = name
		
		name = i['type']
		parameters = i
		try:
			fp, pathname, description = imp.find_module(name, sharelogging.__path__)
			m = imp.load_module(name, fp, pathname, description)
			lo = getattr(m, name)(**parameters)
			loggersShare.append(lo.logShare)
		except:
			logging.getLogger('sharelogging').error("Error setting up share logger %s: %s", name,  sys.exc_info())

	LSbc = []
	if not hasattr(config, 'BitcoinNodeAddresses'):
		config.BitcoinNodeAddresses = ()
	for a in config.BitcoinNodeAddresses:
		LSbc.append(NetworkListener(bcnode, a))
	
	if hasattr(config, 'UpstreamBitcoindNode') and config.UpstreamBitcoindNode:
		BitcoinLink(bcnode, dest=config.UpstreamBitcoindNode)
	
	import jsonrpc_getmemorypool
	import jsonrpc_getwork
	import jsonrpc_setworkaux
	
	server = JSONRPCServer()
	if hasattr(config, 'JSONRPCAddress'):
		logging.getLogger('backwardCompatibility').warn('JSONRPCAddress configuration variable is deprecated; upgrade to JSONRPCAddresses list before 2013-03-05')
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
	server.getBlockTemplate = getBlockTemplate
	server.receiveShare = receiveShare
	server.RaiseRedFlags = RaiseRedFlags
	
	server.TrustedForwarders = ()
	if hasattr(config, 'TrustedForwarders'):
		server.TrustedForwarders = config.TrustedForwarders
	
	restoreState()
	
	bcnode_thr = threading.Thread(target=bcnode.serve_forever)
	bcnode_thr.daemon = True
	bcnode_thr.start()
	
	server.serve_forever()
