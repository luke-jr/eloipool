#!/usr/bin/python3
from config import *
from time import time
now = time()


def RaiseRedFlags(reason):
	# FIXME: Critical-log
	return reason


def makeCoinbaseTxn():
	return b'' # TODO


from merklemaker import merkleMaker
MM = merkleMaker()
MM.UpstreamURI = UpstreamURI
MM.WorkQueueSizeRegular = WorkQueueSizeRegular
MM.WorkQueueSizeLongpoll = WorkQueueSizeLongpoll
MM.TxnUpdateRetryWait = TxnUpdateRetryWait
MM.MinimumTxnUpdateWait = MinimumTxnUpdateWait
MM.IdleSleepTime = IdleSleepTime
MM.makeCoinbaseTxn = makeCoinbaseTxn
MM.start()


def getBlockHeader():
	MRD = MM.getMRD()
	(merkleRoot, merkleTree, coinbaseTxn, prevBlock, bits, rollPrevBlk) = MRD
	timestamp = b'0000'  # FIXME
	hdr = b'\0\0\0\1' + prevBlock + merkleRoot + timestamp + bits + b'\0\0\0\0'
	return (hdr, MRD)


def newBlockNotification(signum, frame):
	MM.updateMerkleTree()
	# TODO: RESPOND TO LONGPOLLS
	pass

from signal import signal, SIGUSR1
signal(SIGUSR1, newBlockNotification)


from jsonrpcServer import JSONRPCServer
import interactiveMode

if __name__ == "__main__":
	server = JSONRPCServer(('', 8444))
	server.getBlockHeader = getBlockHeader
	server.RaiseRedFlags = RaiseRedFlags
	server.serve_forever()
