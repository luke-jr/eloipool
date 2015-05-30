from base58 import b58decode
from util import dblsha

def _Address2PKH(addr):
	try:
		addr = b58decode(addr, 25)
	except:
		return None
	if addr is None:
		return None
	ver = addr[0]
	cksumA = addr[-4:]
	cksumB = dblsha(addr[:-4])[:4]
	if cksumA != cksumB:
		return None
	return (ver, addr[1:-4])

class BitcoinScript:
	@classmethod
	def toAddress(cls, addr):
		d = _Address2PKH(addr)
		if not d:
			raise ValueError('invalid address')
		(ver, pubkeyhash) = d
		if ver == 0 or ver == 111:
			return b'\x76\xa9\x14' + pubkeyhash + b'\x88\xac'
		elif ver == 5 or ver == 196:
			return b'\xa9\x14' + pubkeyhash + b'\x87'
		raise ValueError('invalid address version')

def countSigOps(s):
	# FIXME: don't count data as ops
	c = 0
	for ch in s:
		if 0xac == ch & 0xfe:
			c += 1
		elif 0xae == ch & 0xfe:
			c += 20
	return c
