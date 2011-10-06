from hashlib import sha256

class Txn:
	def __init__(self, data):
		self.data = data
		self.txid = sha256(data).digest()
