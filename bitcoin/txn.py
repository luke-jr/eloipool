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

import bitcoin.script
from .varlen import varlenDecode, varlenEncode
from util import dblsha
from struct import pack, unpack

_nullprev = b'\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0'

class Txn:
	def __init__(self, data=None, txid=None):
		if data:
			self.data = data
			if txid:
				self.txid = txid
			else:
				try:
					self.idhash()
				except NotImplementedError:
					pass
	
	@classmethod
	def new(cls):
		o = cls()
		o.version = 1
		o.inputs = []
		o.outputs = []
		o.locktime = 0
		return o
	
	def setCoinbase(self, sigScript, seqno = 0xffffffff, height = None):
		if not height is None:
			# NOTE: This is required to be the minimum valid length by BIP 34
			sigScript = bitcoin.script.encodeUNum(height) + sigScript
		self.inputs = ( ((_nullprev, 0xffffffff), sigScript, seqno), )
	
	def addInput(self, prevout, sigScript, seqno = 0xffffffff):
		self.inputs.append( (prevout, sigScript, seqno) )
	
	def addOutput(self, amount, pkScript):
		self.outputs.append( (amount, pkScript) )
	
	def disassemble(self, retExtra = False):
		if self.data[4:6] == b'\0\1':
			raise NotImplementedError
		
		self.version = unpack('<L', self.data[:4])[0]
		rc = [4]
		
		(inputCount, data) = varlenDecode(self.data[4:], rc)
		inputs = []
		for i in range(inputCount):
			prevout = (data[:32], unpack('<L', data[32:36])[0])
			rc[0] += 36
			(sigScriptLen, data) = varlenDecode(data[36:], rc)
			sigScript = data[:sigScriptLen]
			seqno = unpack('<L', data[sigScriptLen:sigScriptLen + 4])[0]
			data = data[sigScriptLen + 4:]
			rc[0] += sigScriptLen + 4
			inputs.append( (prevout, sigScript, seqno) )
		self.inputs = inputs
		
		(outputCount, data) = varlenDecode(data, rc)
		outputs = []
		for i in range(outputCount):
			amount = unpack('<Q', data[:8])[0]
			rc[0] += 8
			(pkScriptLen, data) = varlenDecode(data[8:], rc)
			pkScript = data[:pkScriptLen]
			data = data[pkScriptLen:]
			rc[0] += pkScriptLen
			outputs.append( (amount, pkScript) )
		self.outputs = outputs
		
		self.locktime = unpack('<L', data[:4])[0]
		if not retExtra:
			assert len(data) == 4
		else:
			assert data == self.data[rc[0]:]
			data = data[4:]
			rc[0] += 4
			self.data = self.data[:rc[0]]
			return data
	
	def isCoinbase(self):
		return len(self.inputs) == 1 and self.inputs[0][0] == (_nullprev, 0xffffffff)
	
	def getCoinbase(self):
		return self.inputs[0][1]
	
	def assemble(self):
		data = pack('<L', self.version)
		
		inputs = self.inputs
		data += varlenEncode(len(inputs))
		for prevout, sigScript, seqno in inputs:
			data += prevout[0] + pack('<L', prevout[1])
			data += varlenEncode(len(sigScript)) + sigScript
			data += pack('<L', seqno)
		
		outputs = self.outputs
		data += varlenEncode(len(outputs))
		for amount, pkScript in outputs:
			data += pack('<Q', amount)
			data += varlenEncode(len(pkScript)) + pkScript
		
		data += pack('<L', self.locktime)
		
		self.data = data
		self.idhash()
	
	def idhash(self):
		if self.data[4:6] == b'\0\1':
			if hasattr(self, 'txid'):
				del self.txid
			raise NotImplementedError
		self.txid = dblsha(self.data)
		if hasattr(self, 'witness_hash'):
			del self.witness_hash
	
	def withash(self):
		self.witness_hash = dblsha(self.data)
	
	def get_witness_hash(self):
		if not hasattr(self, 'witness_hash'):
			self.withash()
		return self.witness_hash

# Txn tests
def _test():
	d = b'\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00'
	t = Txn(d)
	assert t.txid == b"C\xeczW\x9fUa\xa4*~\x967\xadAVg'5\xa6X\xbe'R\x18\x18\x01\xf7#\xba3\x16\xd2"
	t.disassemble()
	t.assemble()
	assert t.data == d
	assert not t.isCoinbase()
	t = Txn.new()
	t.addInput((b' '*32, 0), b'INPUT')
	t.addOutput(0x10000, b'OUTPUT')
	t.assemble()
	assert t.txid == b'>`\x97\xecu\x8e\xb5\xef\x19k\x17d\x96sw\xb1\xf1\x9bO\x1c6\xa0\xbe\xf7N\xed\x13j\xfdHF\x1a'
	t.disassemble()
	t.assemble()
	assert t.txid == b'>`\x97\xecu\x8e\xb5\xef\x19k\x17d\x96sw\xb1\xf1\x9bO\x1c6\xa0\xbe\xf7N\xed\x13j\xfdHF\x1a'
	assert not t.isCoinbase()
	t = Txn.new()
	t.setCoinbase(b'COINBASE')
	t.addOutput(0x10000, b'OUTPUT')
	assert t.isCoinbase()
	assert t.getCoinbase() == b'COINBASE'
	t.assemble()
	assert t.txid == b'n\xb9\xdc\xef\xe9\xdb(R\x8dC~-\xef~\x88d\x15+X\x13&\xb7\xbc$\xb1h\xf3g=\x9b~V'

_test()
