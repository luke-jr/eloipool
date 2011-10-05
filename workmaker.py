#!/usr/bin/python3
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
		self.data = [None] + data
		self.recalculate()
	
	def recalculate(self):
		L = self.data
		steps = []
		if len(L) > 1:
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
		steps = self._steps
		for s in steps:
			f = dblsha(f + s)
		return f

mt = MerkleTree([a2b_hex(a) for a in [
	'999d2c8bb6bda0bf784d9ebeb631d711dbbbfe1bc006ea13d6ad0d6a2649a971',
	'3f92594d5a3d7b4df29d7dd7c46a0dac39a96e751ba0fc9bab5435ea5e22a19d',
	'a5633f03855f541d8e60a6340fc491d49709dc821f3acb571956a856637adcb6',
	'28d97c850eaf917a4c76c02474b05b70a197eaefb468d21c22ed110afe8ec9e0',
]])
print(b2a_hex(mt.withFirst(a2b_hex('d43b669fb42cfa84695b844c0402d410213faa4f3e66cb7248f688ff19d5e5f7'))))

