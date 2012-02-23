from bitcoinvarlen import varlenDecode, varlenEncode
from util import dblsha
from struct import pack, unpack

_nullprev = b'\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0'

class Txn:
	def __init__(self, data=None):
		if data:
			self.data = data
			self.idhash()
	
	@classmethod
	def new(cls):
		o = cls()
		o.version = 1
		o.inputs = []
		o.outputs = []
		o.locktime = 0
		return o
	
	def setCoinbase(self, sigScript, seqno = 0xffffffff):
		self.inputs = ( ((_nullprev, 0xffffffff), sigScript, seqno), )
	
	def addInput(self, prevout, sigScript, seqno = 0xffffffff):
		self.inputs.append( (prevout, sigScript, seqno) )
	
	def addOutput(self, amount, pkScript):
		self.outputs.append( (amount, pkScript) )
	
	def disassemble(self, retExtra = False):
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
		
		self.locktime = unpack('<L', data)[0]
		if not retExtra:
			assert len(data) == 4
		else:
			assert data == self.data[rc[0]:]
			data = data[4:]
			rc[0] += 4
			self.data = self.data[:rc[0]]
			return data
	
	def isCoinbase(self):
		return len(self.inputs) == 1 and self.inputs[0][1] == 0xffffffff and self.input[0][0] == _nullprev
	
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
		self.txid = dblsha(self.data)
