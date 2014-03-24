#!/usr/bin/python3
# Eloipool - Python Bitcoin pool server
# Copyright (C) 2011-2013  Luke Dashjr <luke-jr+eloipool@utopios.org>
# Portions written by Peter Leurs <kinlo@triplemining.com>
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

import argparse
import importlib
argparser = argparse.ArgumentParser()
argparser.add_argument('-c', '--config', help='Config name to load from config_<ARG>.py')
args = argparser.parse_args()
configmod = 'config'
if not args.config is None:
	configmod = 'config_%s' % (args.config,)
__import__(configmod)
config = importlib.import_module(configmod)

if not hasattr(config, 'ServerName'):
	config.ServerName = 'Unnamed Eloipool'

if not hasattr(config, 'ShareTarget'):
	config.ShareTarget = 0x00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff


import logging
import logging.handlers

rootlogger = logging.getLogger(None)
logformat = getattr(config, 'LogFormat', '%(asctime)s\t%(name)s\t%(levelname)s\t%(message)s')
logformatter = logging.Formatter(logformat)
if len(rootlogger.handlers) == 0:
	logging.basicConfig(
		format=logformat,
		level=logging.DEBUG,
	)
	for infoOnly in (
		'checkShare',
		'getTarget',
		'JSONRPCHandler',
		'JSONRPCServer',
		'merkleMaker',
		'StratumServer',
		'Waker for JSONRPCServer',
		'Waker for StratumServer',
		'WorkLogPruner'
	):
		logging.getLogger(infoOnly).setLevel(logging.INFO)
if getattr(config, 'LogToSysLog', False):
	sysloghandler = logging.handlers.SysLogHandler(address = '/dev/log')
	rootlogger.addHandler(sysloghandler)
if hasattr(config, 'LogFile'):
	if isinstance(config.LogFile, str):
		filehandler = logging.FileHandler(config.LogFile)
	else:
		filehandler = logging.handlers.TimedRotatingFileHandler(**config.LogFile)
	filehandler.setFormatter(logformatter)
	rootlogger.addHandler(filehandler)

def RaiseRedFlags(reason):
	logging.getLogger('redflag').critical(reason)
	return reason


from bitcoin.node import BitcoinLink, BitcoinNode
bcnode = BitcoinNode(config.UpstreamNetworkId)
bcnode.userAgent += b'Eloipool:0.1/'
bcnode.newBlock = lambda blkhash: MM.updateMerkleTree()

import jsonrpc

try:
	import jsonrpc.authproxy
	jsonrpc.authproxy.USER_AGENT = 'Eloipool/0.1'
except:
	pass


from bitcoin.script import BitcoinScript
from bitcoin.txn import Txn
from base58 import b58decode
from binascii import b2a_hex
from struct import pack
import subprocess
from time import time

def makeCoinbaseTxn(coinbaseValue, useCoinbaser = True, prevBlockHex = None):
	txn = Txn.new()
	
	if useCoinbaser and hasattr(config, 'CoinbaserCmd') and config.CoinbaserCmd:
		coinbased = 0
		try:
			cmd = config.CoinbaserCmd
			cmd = cmd.replace('%d', str(coinbaseValue))
			cmd = cmd.replace('%p', prevBlockHex or '""')
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
userStatus = {}
networkTarget = None
DupeShareHACK = {}

server = None
stratumsrv = None
def updateBlocks():
	server.wakeLongpoll()
	stratumsrv.updateJob()

def blockChanged():
	global MM, networkTarget, server
	bits = MM.currentBlock[2]
	if bits is None:
		networkTarget = None
	else:
		networkTarget = Bits2Target(bits)
	if MM.lastBlock != (None, None, None):
		global DupeShareHACK
		DupeShareHACK = {}
		jsonrpc_getwork._CheckForDupesHACK = {}
		workLog.clear()
	server.wakeLongpoll(wantClear=True)
	stratumsrv.updateJob(wantClear=True)


from time import sleep, time
import traceback

def _WorkLogPruner_I(wl):
	now = time()
	pruned = 0
	for username in wl:
		userwork = wl[username]
		for wli in tuple(userwork.keys()):
			if now > userwork[wli][1] + 120:
				del userwork[wli]
				pruned += 1
	WorkLogPruner.logger.debug('Pruned %d jobs' % (pruned,))

def WorkLogPruner(wl):
	while True:
		try:
			sleep(60)
			_WorkLogPruner_I(wl)
		except:
			WorkLogPruner.logger.error(traceback.format_exc())
WorkLogPruner.logger = logging.getLogger('WorkLogPruner')


from merklemaker import merkleMaker
MM = merkleMaker()
MM.__dict__.update(config.__dict__)
MM.makeCoinbaseTxn = makeCoinbaseTxn
MM.onBlockChange = blockChanged
MM.onBlockUpdate = updateBlocks


from binascii import b2a_hex
from copy import deepcopy
from math import ceil, log
from merklemaker import MakeBlockHeader
from struct import pack, unpack
import threading
from time import time
from util import PendingUpstream, RejectedShare, bdiff1target, dblsha, LEhash2int, swap32, target2bdiff, target2pdiff
import jsonrpc
import traceback

gotwork = None
if hasattr(config, 'GotWorkURI'):
	gotwork = jsonrpc.ServiceProxy(config.GotWorkURI)

if not hasattr(config, 'DelayLogForUpstream'):
	config.DelayLogForUpstream = False

if not hasattr(config, 'DynamicTargetting'):
	config.DynamicTargetting = 0
else:
	if not hasattr(config, 'DynamicTargetWindow'):
		config.DynamicTargetWindow = 120
	config.DynamicTargetGoal *= config.DynamicTargetWindow / 60

def submitGotwork(info):
	try:
		gotwork.gotwork(info)
	except:
		checkShare.logger.warning('Failed to submit gotwork\n' + traceback.format_exc())

if not hasattr(config, 'GotWorkTarget'):
	config.GotWorkTarget = 0

def clampTarget(target, DTMode):
	# ShareTarget is the minimum
	if target is None or target > config.ShareTarget:
		target = config.ShareTarget
	
	# Never target above upstream(s), as we'd lose blocks
	target = max(target, networkTarget, config.GotWorkTarget)
	
	if DTMode == 2:
		# Ceil target to a power of two :)
		truebits = log(target, 2)
		if target <= 2**int(truebits):
			# Workaround for bug in Python's math.log function
			truebits = int(truebits)
		target = 2**ceil(truebits) - 1
	elif DTMode == 3:
		# Round target to multiple of bdiff 1
		target = bdiff1target / int(round(target2bdiff(target)))
	
	# Return None for ShareTarget to save memory
	if target == config.ShareTarget:
		return None
	return target

def getTarget(username, now, DTMode = None, RequestedTarget = None):
	if DTMode is None:
		DTMode = config.DynamicTargetting
	if not DTMode:
		return None
	if username in userStatus:
		status = userStatus[username]
	else:
		# No record, use default target
		RequestedTarget = clampTarget(RequestedTarget, DTMode)
		userStatus[username] = [RequestedTarget, now, 0]
		return RequestedTarget
	(targetIn, lastUpdate, work) = status
	if work <= config.DynamicTargetGoal:
		if now < lastUpdate + config.DynamicTargetWindow and (targetIn is None or targetIn >= networkTarget):
			# No reason to change it just yet
			return clampTarget(targetIn, DTMode)
		if not work:
			# No shares received, reset to minimum
			if targetIn:
				getTarget.logger.debug("No shares from %s, resetting to minimum target" % (repr(username),))
				userStatus[username] = [None, now, 0]
			return clampTarget(None, DTMode)
	
	deltaSec = now - lastUpdate
	target = targetIn or config.ShareTarget
	target = int(target * config.DynamicTargetGoal * deltaSec / config.DynamicTargetWindow / work)
	target = clampTarget(target, DTMode)
	if target != targetIn:
		pfx = 'Retargetting %s' % (repr(username),)
		tin = targetIn or config.ShareTarget
		getTarget.logger.debug("%s from: %064x (pdiff %s)" % (pfx, tin, target2pdiff(tin)))
		tgt = target or config.ShareTarget
		getTarget.logger.debug("%s   to: %064x (pdiff %s)" % (pfx, tgt, target2pdiff(tgt)))
	userStatus[username] = [target, now, 0]
	return target
getTarget.logger = logging.getLogger('getTarget')

def TopTargets(n = 0x10):
	tmp = list(k for k, v in userStatus.items() if not v[0] is None)
	tmp.sort(key=lambda k: -userStatus[k][0])
	tmp2 = {}
	def t2d(t):
		if t not in tmp2:
			tmp2[t] = target2pdiff(t)
		return tmp2[t]
	for k in tmp[-n:]:
		tgt = userStatus[k][0]
		print('%-34s %064x %3d' % (k, tgt, t2d(tgt)))

def RegisterWork(username, wli, wld, RequestedTarget = None):
	now = time()
	target = getTarget(username, now, RequestedTarget=RequestedTarget)
	wld = tuple(wld) + (target,)
	workLog.setdefault(username, {})[wli] = (wld, now)
	return target or config.ShareTarget

def getBlockHeader(username):
	MRD = MM.getMRD()
	merkleRoot = MRD[0]
	hdr = MakeBlockHeader(MRD)
	workLog.setdefault(username, {})[merkleRoot] = (MRD, time())
	target = RegisterWork(username, merkleRoot, MRD)
	return (hdr, workLog[username][merkleRoot], target)

def getBlockTemplate(username, p_magic = None, RequestedTarget = None):
	if server.tls.wantClear:
		wantClear = True
	elif p_magic and username not in workLog:
		wantClear = True
		p_magic[0] = True
	else:
		wantClear = False
	MC = MM.getMC(wantClear)
	(dummy, merkleTree, coinbase, prevBlock, bits) = MC[:5]
	wliPos = coinbase[0] + 2
	wliLen = coinbase[wliPos - 1]
	wli = coinbase[wliPos:wliPos+wliLen]
	target = RegisterWork(username, wli, MC, RequestedTarget=RequestedTarget)
	return (MC, workLog[username][wli], target)

def getStratumJob(jobid, wantClear = False):
	MC = MM.getMC(wantClear)
	(dummy, merkleTree, coinbase, prevBlock, bits) = MC[:5]
	now = time()
	workLog.setdefault(None, {})[jobid] = (MC, now)
	return (MC, workLog[None][jobid])

def getExistingStratumJob(jobid):
	wld = workLog[None][jobid]
	return (wld[0], wld)

loggersShare = []
authenticators = []

RBDs = []
RBPs = []

from bitcoin.varlen import varlenEncode, varlenDecode
import bitcoin.txn
from merklemaker import assembleBlock

if not hasattr(config, 'BlockSubmissions'):
	config.BlockSubmissions = None

RBFs = []
def blockSubmissionThread(payload, blkhash, share):
	if config.BlockSubmissions is None:
		servers = list(a for b in MM.TemplateSources for a in b)
	else:
		servers = list(config.BlockSubmissions)
	
	if hasattr(share['merkletree'], 'source_uri'):
		servers.insert(0, {
			'access': jsonrpc.ServiceProxy(share['merkletree'].source_uri),
			'name': share['merkletree'].source,
		})
	elif not servers:
		servers = list(a for b in MM.TemplateSources for a in b)
	
	myblock = (blkhash, payload[4:36])
	payload = b2a_hex(payload).decode('ascii')
	nexterr = 0
	tries = 0
	success = False
	while len(servers):
		tries += 1
		TS = servers.pop(0)
		UpstreamBitcoindJSONRPC = TS['access']
		try:
			# BIP 22 standard submitblock
			reason = UpstreamBitcoindJSONRPC.submitblock(payload)
		except BaseException as gbterr:
			gbterr_fmt = traceback.format_exc()
			try:
				try:
					# bitcoind 0.5/0.6 getmemorypool
					reason = UpstreamBitcoindJSONRPC.getmemorypool(payload)
				except:
					# Old BIP 22 draft getmemorypool
					reason = UpstreamBitcoindJSONRPC.getmemorypool(payload, {})
				if reason is True:
					reason = None
				elif reason is False:
					reason = 'rejected'
			except BaseException as gmperr:
				now = time()
				if now > nexterr:
					# FIXME: This will show "Method not found" on pre-BIP22 servers
					RaiseRedFlags(gbterr_fmt)
					nexterr = now + 5
				if MM.currentBlock[0] not in myblock and tries > len(servers):
					RBFs.append( (('next block', MM.currentBlock, now, (gbterr, gmperr)), payload, blkhash, share) )
					RaiseRedFlags('Giving up on submitting block to upstream \'%s\'' % (TS['name'],))
					if share['upstreamRejectReason'] is PendingUpstream:
						share['upstreamRejectReason'] = 'GAVE UP'
						share['upstreamResult'] = False
						logShare(share)
					return
				
				servers.append(TS)
				continue
		
		# At this point, we have a reason back
		if reason:
			# FIXME: The returned value could be a list of multiple responses
			msg = 'Upstream \'%s\' block submission failed: %s' % (TS['name'], reason,)
			if success and reason in ('stale-prevblk', 'bad-prevblk', 'orphan', 'duplicate'):
				# no big deal
				blockSubmissionThread.logger.debug(msg)
			else:
				RBFs.append( (('upstream reject', reason, time()), payload, blkhash, share) )
				RaiseRedFlags(msg)
		else:
			blockSubmissionThread.logger.debug('Upstream \'%s\' accepted block' % (TS['name'],))
			success = True
		if share['upstreamRejectReason'] is PendingUpstream:
			share['upstreamRejectReason'] = reason
			share['upstreamResult'] = not reason
			logShare(share)
blockSubmissionThread.logger = logging.getLogger('blockSubmission')

def checkData(share):
	data = share['data']
	data = data[:80]
	(prevBlock, height, bits) = MM.currentBlock
	sharePrevBlock = data[4:36]
	if sharePrevBlock != prevBlock:
		if sharePrevBlock == MM.lastBlock[0]:
			raise RejectedShare('stale-prevblk')
		raise RejectedShare('bad-prevblk')
	
	if data[72:76] != bits:
		raise RejectedShare('bad-diffbits')
	
	# Note that we should accept miners reducing version to 1 if they don't understand 2 yet
	# FIXME: When the supermajority is upgraded to version 2, stop accepting 1!
	if data[1:4] != b'\0\0\0' or data[0] > 2:
		raise RejectedShare('bad-version')

def buildStratumData(share, merkleroot):
	(prevBlock, height, bits) = MM.currentBlock
	
	data = b'\x02\0\0\0'
	data += prevBlock
	data += merkleroot
	data += share['ntime'][::-1]
	data += bits
	data += share['nonce'][::-1]
	
	share['data'] = data
	return data

def IsJobValid(wli, wluser = None):
	if wluser not in workLog:
		return False
	if wli not in workLog[wluser]:
		return False
	(wld, issueT) = workLog[wluser][wli]
	if time() < issueT - 120:
		return False
	return True

def checkShare(share):
	shareTime = share['time'] = time()
	
	username = share['username']
	isstratum = False
	if 'data' in share:
		# getwork/GBT
		checkData(share)
		data = share['data']
		
		if username not in workLog:
			raise RejectedShare('unknown-user')
		MWL = workLog[username]
		
		shareMerkleRoot = data[36:68]
		if 'blkdata' in share:
			pl = share['blkdata']
			(txncount, pl) = varlenDecode(pl)
			cbtxn = bitcoin.txn.Txn(pl)
			othertxndata = cbtxn.disassemble(retExtra=True)
			coinbase = cbtxn.getCoinbase()
			wliPos = coinbase[0] + 2
			wliLen = coinbase[wliPos - 1]
			wli = coinbase[wliPos:wliPos+wliLen]
			mode = 'MC'
			moden = 1
		else:
			wli = shareMerkleRoot
			mode = 'MRD'
			moden = 0
			coinbase = None
	else:
		# Stratum
		isstratum = True
		wli = share['jobid']
		buildStratumData(share, b'\0' * 32)
		mode = 'MC'
		moden = 1
		othertxndata = b''
		if None not in workLog:
			# We haven't yet sent any stratum work for this block
			raise RejectedShare('unknown-work')
		MWL = workLog[None]
	
	if wli not in MWL:
		raise RejectedShare('unknown-work')
	(wld, issueT) = MWL[wli]
	share[mode] = wld
	
	share['issuetime'] = issueT
	
	(workMerkleTree, workCoinbase) = wld[1:3]
	share['merkletree'] = workMerkleTree
	if 'jobid' in share:
		cbtxn = deepcopy(workMerkleTree.data[0])
		coinbase = workCoinbase + share['extranonce1'] + share['extranonce2']
		cbtxn.setCoinbase(coinbase)
		cbtxn.assemble()
		data = buildStratumData(share, workMerkleTree.withFirst(cbtxn))
		shareMerkleRoot = data[36:68]
	
	if data in DupeShareHACK:
		raise RejectedShare('duplicate')
	DupeShareHACK[data] = None
	
	blkhash = dblsha(data)
	if blkhash[28:] != b'\0\0\0\0':
		raise RejectedShare('H-not-zero')
	blkhashn = LEhash2int(blkhash)
	
	global networkTarget
	logfunc = getattr(checkShare.logger, 'info' if blkhashn <= networkTarget else 'debug')
	logfunc('BLKHASH: %64x' % (blkhashn,))
	logfunc(' TARGET: %64x' % (networkTarget,))
	
	# NOTE: this isn't actually needed for MC mode, but we're abusing it for a trivial share check...
	txlist = workMerkleTree.data
	txlist = [deepcopy(txlist[0]),] + txlist[1:]
	cbtxn = txlist[0]
	cbtxn.setCoinbase(coinbase or workCoinbase)
	cbtxn.assemble()
	
	if blkhashn <= networkTarget:
		logfunc("Submitting upstream")
		RBDs.append( deepcopy( (data, txlist, share.get('blkdata', None), workMerkleTree, share, wld) ) )
		if not moden:
			payload = assembleBlock(data, txlist)
		else:
			payload = share['data']
			if len(othertxndata):
				payload += share['blkdata']
			else:
				payload += assembleBlock(data, txlist)[80:]
		logfunc('Real block payload: %s' % (b2a_hex(payload).decode('utf8'),))
		RBPs.append(payload)
		threading.Thread(target=blockSubmissionThread, args=(payload, blkhash, share)).start()
		bcnode.submitBlock(payload)
		if config.DelayLogForUpstream:
			share['upstreamRejectReason'] = PendingUpstream
		else:
			share['upstreamRejectReason'] = None
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
	
	if 'target' in share:
		workTarget = share['target']
	elif len(wld) > 6:
		workTarget = wld[6]
	else:
		workTarget = None
	
	if workTarget is None:
		workTarget = config.ShareTarget
	if blkhashn > workTarget:
		raise RejectedShare('high-hash')
	share['target'] = workTarget
	share['_targethex'] = '%064x' % (workTarget,)
	
	shareTimestamp = unpack('<L', data[68:72])[0]
	if shareTime < issueT - 120:
		raise RejectedShare('stale-work')
	if shareTimestamp < shareTime - 300:
		raise RejectedShare('time-too-old')
	if shareTimestamp > shareTime + 7200:
		raise RejectedShare('time-too-new')
	
	if moden:
		cbpre = workCoinbase
		cbpreLen = len(cbpre)
		if coinbase[:cbpreLen] != cbpre:
			raise RejectedShare('bad-cb-prefix')
		
		# Filter out known "I support" flags, to prevent exploits
		for ff in (b'/P2SH/', b'NOP2SH', b'p2sh/CHV', b'p2sh/NOCHV'):
			if coinbase.find(ff) > max(-1, cbpreLen - len(ff)):
				raise RejectedShare('bad-cb-flag')
		
		if len(coinbase) > 100:
			raise RejectedShare('bad-cb-length')
		
		if shareMerkleRoot != workMerkleTree.withFirst(cbtxn):
			raise RejectedShare('bad-txnmrklroot')
		
		if len(othertxndata):
			allowed = assembleBlock(data, txlist)[80:]
			if allowed != share['blkdata']:
				raise RejectedShare('bad-txns')
	
	if config.DynamicTargetting and username in userStatus:
		# NOTE: userStatus[username] only doesn't exist across restarts
		status = userStatus[username]
		target = status[0] or config.ShareTarget
		if target == workTarget:
			userStatus[username][2] += 1
		else:
			userStatus[username][2] += float(target) / workTarget
		if isstratum and userStatus[username][2] > config.DynamicTargetGoal * 2:
			stratumsrv.quickDifficultyUpdate(username)
checkShare.logger = logging.getLogger('checkShare')

def logShare(share):
	if '_origdata' in share:
		share['solution'] = share['_origdata']
	else:
		share['solution'] = b2a_hex(swap32(share['data'])).decode('utf8')
	for i in loggersShare:
		i.logShare(share)

def checkAuthentication(username, password):
	# HTTPServer uses bytes, and StratumServer uses str
	if hasattr(username, 'decode'): username = username.decode('utf8')
	if hasattr(password, 'decode'): password = password.decode('utf8')
	
	for i in authenticators:
		if i.checkAuthentication(username, password):
			return True
	return False

def receiveShare(share):
	# TODO: username => userid
	try:
		checkShare(share)
	except RejectedShare as rej:
		share['rejectReason'] = str(rej)
		raise
	except BaseException as e:
		share['rejectReason'] = 'ERROR'
		raise
	finally:
		if not share.get('upstreamRejectReason', None) is PendingUpstream:
			logShare(share)

def newBlockNotification():
	logging.getLogger('newBlockNotification').info('Received new block notification')
	MM.updateMerkleTree()
	# TODO: Force RESPOND TO LONGPOLLS?
	pass

def newBlockNotificationSIGNAL(signum, frame):
	# Use a new thread, in case the signal handler is called with locks held
	thr = threading.Thread(target=newBlockNotification, name='newBlockNotification via signal %s' % (signum,))
	thr.daemon = True
	thr.start()

from signal import signal, SIGUSR1
signal(SIGUSR1, newBlockNotificationSIGNAL)


import os
import os.path
import pickle
import signal
import sys
from time import sleep
import traceback

if getattr(config, 'SaveStateFilename', None) is None:
	config.SaveStateFilename = 'eloipool.worklog'

def stopServers():
	logger = logging.getLogger('stopServers')
	
	if hasattr(stopServers, 'already'):
		logger.debug('Already tried to stop servers before')
		return
	stopServers.already = True
	
	logger.info('Stopping servers...')
	global bcnode, server
	servers = (bcnode, server, stratumsrv)
	for s in servers:
		s.keepgoing = False
	for s in servers:
		try:
			s.wakeup()
		except:
			logger.error('Failed to stop server %s\n%s' % (s, traceback.format_exc()))
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

def stopLoggers():
	for i in loggersShare:
		if hasattr(i, 'stop'):
			i.stop()

def saveState(SAVE_STATE_FILENAME, t = None):
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
	stopLoggers()
	saveState(config.SaveStateFilename, t=t)
	logging.getLogger('exit').info('Goodbye...')
	os.kill(os.getpid(), signal.SIGTERM)
	sys.exit(0)

def restart():
	t = time()
	stopServers()
	stopLoggers()
	saveState(config.SaveStateFilename, t=t)
	logging.getLogger('restart').info('Restarting...')
	try:
		os.execv(sys.argv[0], sys.argv)
	except:
		logging.getLogger('restart').error('Failed to exec\n' + traceback.format_exc())

def restoreState(SAVE_STATE_FILENAME):
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
				if len(t) > 2:
					# Future formats, not supported here
					ver = t[3]
					# TODO
				
				# Old format, from 2012-02-02 to 2012-02-03
				workLog = t[0]
				DupeShareHACK = t[1]
				t = None
			else:
				if isinstance(t, dict):
					# Old format, from 2012-02-03 to 2012-02-03
					DupeShareHACK = t
					t = None
				else:
					# Current format, from 2012-02-03 onward
					DupeShareHACK = pickle.load(f)
				
				if t + 120 >= time():
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
import authentication
from stratumserver import StratumServer
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
			loggersShare.append(lo)
		except:
			logging.getLogger('sharelogging').error("Error setting up share logger %s: %s", name,  sys.exc_info())
	
	if not hasattr(config, 'Authentication'):
		config.Authentication = ({'module': 'allowall'},)
	
	for i in config.Authentication:
		name = i['module']
		parameters = i
		try:
			fp, pathname, description = imp.find_module(name, authentication.__path__)
			m = imp.load_module(name, fp, pathname, description)
			lo = getattr(m, name)(**parameters)
			authenticators.append(lo)
		except:
			logging.getLogger('authentication').error("Error setting up authentication module %s: %s", name, sys.exc_info())
	
	LSbc = []
	if not hasattr(config, 'BitcoinNodeAddresses'):
		config.BitcoinNodeAddresses = ()
	for a in config.BitcoinNodeAddresses:
		LSbc.append(NetworkListener(bcnode, a))
	
	if hasattr(config, 'UpstreamBitcoindNode') and config.UpstreamBitcoindNode:
		BitcoinLink(bcnode, dest=config.UpstreamBitcoindNode)
	
	import jsonrpc_getblocktemplate
	import jsonrpc_getwork
	import jsonrpc_setworkaux
	
	server = JSONRPCServer()
	server.tls = threading.local()
	server.tls.wantClear = False
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
	server.ShareTarget = config.ShareTarget
	server.checkAuthentication = checkAuthentication
	
	if hasattr(config, 'TrustedForwarders'):
		server.TrustedForwarders = config.TrustedForwarders
	server.ServerName = config.ServerName
	
	stratumsrv = StratumServer()
	stratumsrv.getStratumJob = getStratumJob
	stratumsrv.getExistingStratumJob = getExistingStratumJob
	stratumsrv.receiveShare = receiveShare
	stratumsrv.RaiseRedFlags = RaiseRedFlags
	stratumsrv.getTarget = getTarget
	stratumsrv.defaultTarget = config.ShareTarget
	stratumsrv.IsJobValid = IsJobValid
	stratumsrv.checkAuthentication = checkAuthentication
	if not hasattr(config, 'StratumAddresses'):
		config.StratumAddresses = ()
	for a in config.StratumAddresses:
		NetworkListener(stratumsrv, a)
	
	MM.start()
	
	restoreState(config.SaveStateFilename)
	
	prune_thr = threading.Thread(target=WorkLogPruner, args=(workLog,))
	prune_thr.daemon = True
	prune_thr.start()
	
	bcnode_thr = threading.Thread(target=bcnode.serve_forever)
	bcnode_thr.daemon = True
	bcnode_thr.start()
	
	stratum_thr = threading.Thread(target=stratumsrv.serve_forever)
	stratum_thr.daemon = True
	stratum_thr.start()
	
	server.serve_forever()
