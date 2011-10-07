from hashlib import sha256
from struct import unpack

def dblsha(b):
	return sha256(sha256(b).digest()).digest()

def swap32(b):
	o = b''
	for i in range(0, len(b), 4):
		o += b[i + 3:i - 1 if i else None:-1]
	return o

def Bits2Target(bits):
	return unpack('<L', bits[:3] + b'\0')[0] * 2**(8*(bits[3] - 3))

def hash2int(h):
	n = unpack('<QQQQ', h)
	n = (n[3] << 192) | (n[2] << 128) | (n[1] << 64) | n[0]
	return n

class RejectedShare(ValueError):
	pass
