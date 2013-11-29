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

try:
	from bitcoin.txn import Txn
except ImportError:
	class Txn:
		pass
from util import dblsha

class MerkleTree:
	def __init__(self, data, detailed=False):
		self.data = data
		self.recalculate(detailed)
	
	def recalculate(self, detailed=False):
		L = self.data
		steps = []
		if detailed:
			detail = []
			PreL = []
			StartL = 0
		else:
			detail = None
			PreL = [None]
			StartL = 2
		Ll = len(L)
		if detailed or Ll > 1:
			if isinstance(L[1] if Ll > 1 else L[0], Txn):
				L = list(map(lambda a: a.txid if a else a, L))
			while True:
				if detailed:
					detail += L
				if Ll == 1:
					break
				steps.append(L[1])
				if Ll % 2:
					L += [L[-1]]
				L = PreL + [dblsha(L[i] + L[i + 1]) for i in range(StartL, Ll, 2)]
				Ll = len(L)
		self._steps = steps
		self.detail = detail
	
	def withFirst(self, f):
		if isinstance(f, Txn):
			f = f.txid
		steps = self._steps
		for s in steps:
			f = dblsha(f + s)
		return f
	
	def merkleRoot(self):
		return self.withFirst(self.data[0])

# MerkleTree tests
def _test():
	if not hasattr(bytes, 'fromhex'):
		return
	from binascii import b2a_hex
	mt = MerkleTree([None] + [bytes.fromhex(a) for a in [
		'999d2c8bb6bda0bf784d9ebeb631d711dbbbfe1bc006ea13d6ad0d6a2649a971',
		'3f92594d5a3d7b4df29d7dd7c46a0dac39a96e751ba0fc9bab5435ea5e22a19d',
		'a5633f03855f541d8e60a6340fc491d49709dc821f3acb571956a856637adcb6',
		'28d97c850eaf917a4c76c02474b05b70a197eaefb468d21c22ed110afe8ec9e0',
	]])
	assert(
		b'82293f182d5db07d08acf334a5a907012bbb9990851557ac0ec028116081bd5a' ==
		b2a_hex(mt.withFirst(bytes.fromhex('d43b669fb42cfa84695b844c0402d410213faa4f3e66cb7248f688ff19d5e5f7')))
	)
	
	d = b'\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00'
	dh = b"C\xeczW\x9fUa\xa4*~\x967\xadAVg'5\xa6X\xbe'R\x18\x18\x01\xf7#\xba3\x16\xd2"
	t = Txn(d)
	m = MerkleTree([t])
	assert m.merkleRoot() == dh
	u = Txn.new()
	u.addInput((b' '*32, 0), b'')
	u.assemble()
	m.data.append(u)
	m.recalculate()
	mr = b"q\xe1\x9a3'\x0f>\xbfTv\xc8\x90\x81\x802\xe3\xb7u\x96\xddjP4\xe3\x19\xf3\xf0\xc5A4\xc0\xdb"
	assert m.merkleRoot() == mr
	step = b'\xb0\x91t\x84%\x9dg\x827\xc5\xbf\x94\xf0"\x94\xafN[\x0c\xeelF\xd9\x1b\x13q\xd3\xdf\x83\xe6\x01g'
	assert m._steps == [step]
	m.recalculate(detailed=True)
	assert m.detail == [dh, step, mr]
	m = MerkleTree([t.txid, u.txid])
	assert m.merkleRoot() == mr
	assert m._steps == [step]
	m.recalculate(detailed=True)
	assert m.detail == [dh, step, mr]

_test()
