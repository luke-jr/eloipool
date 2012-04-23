from bitcoinvarlen import varlenDecode, varlenEncode
from dblsha import dblsha
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
	
	def disassemble(self):
		self.version = unpack('<L', self.data[:4])
		
		(inputCount, data) = varlenDecode(self.data[4:])
		inputs = []
		for i in range(inputCount):
			prevout = (data[:32], unpack('<L', data[32:36]))
			(sigScript, data) = varlenDecode(data[36:])
			sigScript = data[:sigScript]
			seqno = unpack('<L', data[sigScript:sigScript + 4])
			data = data[sigScript + 4:]
			inputs.append( (prevout, sigScript, seqno) )
		self.inputs = inputs
		
		(outputCount, data) = varlenDecode(self.data[4:])
		outputs = []
		for i in range(outputCount):
			amount = unpack('<Q', data[:8])
			(pkScript, data) = varlenDecode(data[8:])
			pkScript = data[:pkScript]
			data = data[pkScript:]
			outputs.append( (amount, pkScript) )
		self.outputs = outputs
		
		assert len(data) == 4
		self.locktime = unpack('<L', data)
	
	def isCoinbase(self):
		return len(self.inputs) == 1 and self.inputs[0][1] == 0xffffffff and self.inputs[0][0] == _nullprev
	
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
		for amount, pkScript in inputs:
			data += pack('<Q', amount)
			data += varlenEncode(len(pkScript)) + pkScript
		
		data += pack('<L', self.locktime)
		
		self.data = data
		self.idhash()
	
	def idhash(self):
		self.txid = dblsha(self.data)
