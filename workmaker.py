#!/usr/bin/python3
from config import *
from time import time
now = time()


def RaiseRedFlags(reason):
	# FIXME: Critical-log
	return reason


def makeCoinbaseTxn():
	return b'' # TODO


from hashlib import sha256
from binascii import a2b_hex, b2a_hex

def dblsha(b):
	return sha256(sha256(b).digest()).digest()

class Txn:
	def __init__(self, data):
		self.data = data
		self.txid = sha256(data).digest()

class MerkleTree:
	def __init__(self, data):
		self.data = data
		self.recalculate()
	
	def recalculate(self):
		L = self.data
		steps = []
		if len(L) > 1:
			if isinstance(L[1], Txn):
				L = list(map(lambda a: a.txid if a else a, L))
			while True:
				Ll = len(L)
				steps.append(L[1])
				if Ll == 2:
					break
				if Ll % 2:
					L += [L[-1]]
				L = [None] + [dblsha(L[i] + L[i + 1]) for i in range(2, Ll, 2)]
		self._steps = steps
	
	def withFirst(self, f):
		if isinstance(f, Txn):
			f = f.txid
		steps = self._steps
		for s in steps:
			f = dblsha(f + s)
		return f
	
	def merkleRoot(self):
		return self.withFirst(self.data[0])

# MerkleTree test case
mt = MerkleTree([None] + [a2b_hex(a) for a in [
	'999d2c8bb6bda0bf784d9ebeb631d711dbbbfe1bc006ea13d6ad0d6a2649a971',
	'3f92594d5a3d7b4df29d7dd7c46a0dac39a96e751ba0fc9bab5435ea5e22a19d',
	'a5633f03855f541d8e60a6340fc491d49709dc821f3acb571956a856637adcb6',
	'28d97c850eaf917a4c76c02474b05b70a197eaefb468d21c22ed110afe8ec9e0',
]])
assert(
	b'82293f182d5db07d08acf334a5a907012bbb9990851557ac0ec028116081bd5a' ==
	b2a_hex(mt.withFirst(a2b_hex('d43b669fb42cfa84695b844c0402d410213faa4f3e66cb7248f688ff19d5e5f7')))
)


from collections import deque
from queue import Queue

currentBlock = (None, None)
currentMerkleTree = None
merkleRoots = deque(maxlen=WorkQueueSizeRegular[1])
clearMerkleTree = MerkleTree([None])
clearMerkleRoots = Queue(WorkQueueSizeLongpoll[1])

def getBlockHeader():
	global currentBlock, currentMerkleTree, merkleRoots, clearMerkleRoots
	(prevBlock, bits) = currentBlock
	try:
		(merkleRoot, merkleTree, coinbaseTxn) = merkleRoots.pop()
		MRD = (merkleRoot, merkleTree, coinbaseTxn, prevBlock, bits)
	except IndexError:
		(merkleRoot, merkleTree, coinbaseTxn) = clearMerkleRoots.get()
		MRD = (merkleRoot, merkleTree, coinbaseTxn, None, None)
	timestamp = b'0000'
	hdr = b'\0\0\0\1' + prevBlock + merkleRoot + timestamp + bits + b'\0\0\0\0'
	return (hdr, (merkleRoot, prevBlock, bits, merkleTree, coinbaseTxn))


import jsonrpc
from threading import Thread
from time import sleep, time
import traceback
import sys # for debugging

access = jsonrpc.ServiceProxy(UpstreamURI)

nextMerkleUpdate = 0
def updateMerkleTree():
	sys.stdout.write("\nUPDATE ")
	global now, currentBlock, currentMerkleTree, merkleRoots, nextMerkleUpdate
	nextMerkleUpdate = now + TxnUpdateRetryWait
	MP = access.getmemorypool()
	prevBlock = a2b_hex(MP['previousblockhash'])
	if prevBlock != currentBlock[0]:
		merkleRoots.clear()
		# TODO: Discard all work logs
		currentMerkleTree = MerkleTree([None])
		bits = a2b_hex(MP['bits'])
		currentBlock = (prevBlock, bits)
	txnlist = map(Txn, map(a2b_hex, MP['transactions']))
	txnlist = [None] + list(txnlist)
	newMerkleTree = MerkleTree(txnlist)
	if newMerkleTree.withFirst(b'') != currentMerkleTree.withFirst(b''):
		currentMerkleTree = newMerkleTree
	nextMerkleUpdate = now + MinimumTxnUpdateWait
updateMerkleTree()

def makeMerkleRoot(merkleTree):
	coinbaseTxn = makeCoinbaseTxn()
	merkleRoot = merkleTree.withFirst(coinbaseTxn)
	return (merkleRoot, merkleTree, coinbaseTxn)

def merkleMaker_I():
	global now, currentBlock, currentMerkleTree, merkleRoots, clearMerkleRoots
	
	# First, update merkle tree if we haven't for a while and aren't crunched for time
	now = time()
	if nextMerkleUpdate <= now and clearMerkleRoots.qsize() > WorkQueueSizeLongpoll[0] and len(merkleRoots) > WorkQueueSizeRegular[0]:
		updateMerkleTree()
	# Next, fill up the longpoll queue first, since it can be used as a failover for the main queue
	elif not clearMerkleRoots.full():
		sys.stdout.write("CLR ")
		clearMerkleRoots.put(makeMerkleRoot(clearMerkleTree))
	# Next, fill up the main queue (until they're all current)
	elif len(merkleRoots) < WorkQueueSizeRegular[1]: # or merkleRoots[0][1] != currentMerkleTree:
		sys.stdout.write("REG ")
		merkleRoots.append(makeMerkleRoot(clearMerkleTree))
	else:
		sys.stdout.write(".")
		# TODO: rather than sleepspin, block until MinimumTxnUpdateWait expires or threading.Condition(?)
		sleep(IdleSleepTime)
	sys.stdout.flush()

def merkleMaker():
	while True:
		try:
			merkleMaker_I()
		except:
			print(traceback.format_exc())

merkleMakerThread = Thread(target=merkleMaker, name='merkleMaker')
merkleMakerThread.daemon = True
merkleMakerThread.start()


def newBlockNotification(signum, frame):
	updateMerkleTree()
	# TODO: RESPOND TO LONGPOLLS
	pass

from signal import signal, SIGUSR1
signal(SIGUSR1, newBlockNotification)


from base64 import b64decode
from binascii import b2a_hex
from datetime import datetime
from email.utils import formatdate
import json
import socketserver
from time import mktime
import traceback

# TODO: keepalive/close
_CheckForDupesHACK = {}
class MyTCPHandler(socketserver.StreamRequestHandler):
	HTTPStatus = {
		200: 'OK',
		401: 'Unauthorized',
		404: 'Not Found',
		405: 'Method Not Allowed',
		500: 'Internal Server Error',
	}
	
	def sendReply(self, status=200, body=b'', headers=None):
		wfile = self.wfile
		buf = "HTTP/1.1 %d Eligius\n" % (status,)
		headers = dict(headers) if headers else {}
		headers['Date'] = formatdate(timeval=mktime(datetime.now().timetuple()), localtime=False, usegmt=True)
		if body is None:
			headers.setdefault('Transfer-Encoding', 'chunked')
			body = b''
		else:
			headers['Content-Length'] = len(body)
		if status == 200:
			headers.setdefault('Content-Type', 'application/json')
			#headers.setdefault('X-Long-Polling', '/LP')
		for k, v in headers.items():
			if v is None: continue
			buf += "%s: %s\n" % (k, v)
		buf += "\n"
		buf = buf.encode('utf8')
		buf += body
		wfile.write(buf)
	
	def doError(self, reason = ''):
		return self.sendReply(500, reason.encode('utf8'))
	
	def doHeader_authorization(self, value):
		value = value.split(b' ')
		if len(value) != 2 or value[0] != b'Basic':
			return self.doError('Bad Authorization header')
		value = b64decode(value[1])
		value = value.split(b':')[0]
		self.Username = value
	
	def doHeader_content_length(self, value):
		self.CL = int(value)
	
	def doAuthenticate(self):
		self.sendReply(401, headers={'WWW-Authenticate': 'Basic realm="Eligius"'})
	
	def doLongpoll(self):
		pass # TODO
	
	def doJSON(self, data):
		# TODO: handle JSON errors
		data = data.decode('utf8')
		data = json.loads(data)
		method = 'doJSON_' + str(data['method']).lower()
		if not hasattr(self, method):
			return self.doError('No such method')
		# TODO: handle errors as JSON-RPC
		rv = getattr(self, method)(*tuple(data['params']))
		rv = {'id': data['id'], 'error': None, 'result': rv}
		rv = json.dumps(rv)
		rv = rv.encode('utf8')
		return self.sendReply(200, rv)
	
	getwork_rv_template = {
		'target': 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffff00000000',
		'hash1': '00000000000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000010000',
	}
	def doJSON_getwork(self, data=None):
		if not data is None:
			return self.doJSON_submitwork(data)
		rv = dict(self.getwork_rv_template)
		(hdr, MRD) = getBlockHeader()
		
		# FIXME: this assumption breaks with noncerange or pool-side rollntime
		global _CheckForDupesHACK
		if hdr in _CheckForDupesHACK:
			raise RaiseRedFlags(RuntimeError('issuing duplicate work'))
		_CheckForDupesHACK[hdr] = None
		
		data = b2a_hex(hdr).decode('utf8')
		# TODO: endian shuffle etc
		rv['data'] = data
		# TODO: rv['midstate'] = 
		return rv
	
	def doJSON_submitwork(self, data):
		return 'TODO'  # TODO
		pass
	
	def handle(self):
		# TODO: handle socket errors
		rfile = self.rfile
		data = rfile.readline().strip()
		data = data.split(b' ')
		if not data[0] in (b'GET', b'POST'):
			return self.sendReply(405)
		path = data[1]
		if not path in (b'/', b'/LP'):
			return self.sendReply(404)
		self.CL = None
		self.Username = None
		while True:
			data = rfile.readline().strip()
			if not data:
				break
			data = tuple(map(lambda a: a.strip(), data.split(b':', 1)))
			method = 'doHeader_' + data[0].decode('ascii').lower()
			if hasattr(self, method):
				getattr(self, method)(data[1])
		if not self.Username:
			return self.doAuthenticate()
		data = rfile.read(self.CL) if self.CL else None
		try:
			if path == b'/LP':
				return self.doLongpoll()
			return self.doJSON(data)
		except:
			print(traceback.format_exc())
			return self.doError('uncaught error')
setattr(MyTCPHandler, 'doHeader_content-length', MyTCPHandler.doHeader_content_length);

class MyTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
	allow_reuse_address = True


def _RunCLI():
    import code, threading
    namespace = globals()

    def CLI():
        code.interact(banner=None, local=namespace)
    threading.Timer(0, CLI).start()

if __name__ == "__main__":
	server = MyTCPServer(('', 8444), MyTCPHandler)
	_RunCLI()
	server.serve_forever()
