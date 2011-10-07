from bitcoinvarlen import varlenEncode
import socket
from struct import pack, unpack
from time import time
from util import dblsha

class BitcoinLink:
	def __init__(self, dest, netid):
		self.netid = netid
		sck = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sck.connect(dest)
		self.sock = sck
		destAddr = self.makeNetAddr(sck.getpeername())
		payload = b'\0\0\1\0\0\0\0\0\0\0\0\0' + pack('<L', int(time())) + destAddr
		self.sendMessage('version', payload, cksum=False)
		self._flushrecv()
	
	def _flushrecv(self):
		try:
			while len(self.sock.recv(1024, socket.MSG_DONTWAIT)):
				pass
		except socket.error:
			pass
	
	def makeMessage(self, cmd, payload, cksum = True):
		cmd = cmd.encode('utf8')
		assert len(cmd) <= 12
		cmd += b'\0' * (12 - len(cmd))
		payload += dblsha(payload)[:4] if cksum else b''
		payloadLen = pack('<L', len(payload))
		return self.netid + cmd + payloadLen + payload
	
	def sendMessage(self, *a, **k):
		return self.sock.send(self.makeMessage(*a, **k))
	
	def makeNetAddr(self, addr):
		timestamp = pack('<L', int(time()))
		aIP = pack('>BBBB', *map(int, addr[0].split('.')))
		aPort = pack('>H', addr[1])
		return timestamp + b'\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xff\xff' + aIP + aPort
	
	def submitBlock(self, blkhdr, txlist):
		self._flushrecv()
		sck = self.sock
		payload = blkhdr
		payload += varlenEncode(len(txlist))
		for tx in txlist:
			payload += tx.data
		self.sendMessage('block', payload)
		self._flushrecv()
