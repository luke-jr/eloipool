from hashlib import sha256

def dblsha(b):
	return sha256(sha256(b).digest()).digest()
