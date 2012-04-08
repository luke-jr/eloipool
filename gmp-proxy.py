#!/usr/bin/python3

import logging
logging.basicConfig(level=logging.DEBUG)

from binascii import a2b_hex, b2a_hex
import bitcoin.txn
import bitcoin.varlen
import jsonrpc
import jsonrpcserver
import merkletree
from struct import pack
import sys
from time import time
from util import RejectedShare

pool = jsonrpc.ServiceProxy(sys.argv[1])

worklog = {}

def MakeWork(username):
	mp = pool.getmemorypool()
	coinbase = a2b_hex(mp['coinbasetxn'])
	cbtxn = bitcoin.txn.Txn(coinbase)
	txnlist = [cbtxn,] + list(map(bitcoin.txn.Txn, map(a2b_hex, mp['transactions'])))
	merkleTree = merkletree.MerkleTree(txnlist)
	merkleRoot = merkleTree.merkleRoot()
	prevBlock = a2b_hex(mp['previousblockhash'])[::-1]
	bits = a2b_hex(mp['bits'])[::-1]
	rollPrevBlk = False
	
	MRD = (merkleRoot, merkleTree, coinbase, prevBlock, bits, rollPrevBlk)
	timestamp = pack('<L', int(time()))
	hdr = b'\1\0\0\0' + prevBlock + merkleRoot + timestamp + bits + b'ppmg'
	worklog[hdr[4:68]] = (MRD, time())
	return hdr

def SubmitShare(share):
	hdr = share['data'][:80]
	k = hdr[4:68]
	if k not in worklog:
		raise RejectedShare('LOCAL unknown-work')
	(MRD, issueT) = worklog[k]
	(merkleRoot, merkleTree, coinbase, prevBlock, bits, rollPrevBlk) = MRD
	blkdata = bitcoin.varlen.varlenEncode(len(merkleTree.data))
	for txn in merkleTree.data:
		blkdata += txn.data
	data = b2a_hex(hdr + blkdata).decode('utf8')
	rejReason = pool.submitblock(data)
	if not rejReason is None:
		raise RejectedShare('pool-' + rejReason)

server = jsonrpcserver.JSONRPCServer()
server.getBlockHeader = MakeWork
server.receiveShare = SubmitShare
jsonrpcserver.JSONRPCListener(server, ('::ffff:127.0.0.1', 9332))

server.serve_forever()
