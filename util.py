from hashlib import sha256
from struct import unpack
import traceback

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

def tryErr(func, *a, **kw):
	IE = kw.pop('IgnoredExceptions', BaseException)
	logger = kw.pop('Logger', None)
	try:
		return func(*a, **kw)
	except IE:
		if logger:
			logger.error(traceback.format_exc())
		return None

class RejectedShare(ValueError):
	pass


import heapq

class ScheduleDict:
	def __init__(self):
		self._dict = {}
		self._build_heap()
	
	def _build_heap(self):
		newheap = list((v[0], k, v[1]) for k, v in self._dict.values())
		heapq.heapify(newheap)
		self._heap = newheap
	
	def nextTime(self):
		while True:
			(t, k, o) = self._heap[0]
			if k in self._dict:
				break
			heapq.heappop(self._heap)
		return t
	
	def shift(self):
		while True:
			(t, k, o) = heapq.heappop(self._heap)
			if k in self._dict:
				break
		del self._dict[k]
		return o
	
	def __setitem__(self, o, t):
		k = id(o)
		self._dict[k] = (t, o)
		if len(self._heap) / 2 > len(self._dict):
			self._build_heap()
		else:
			heapq.heappush(self._heap, (t, k, o))
	
	def __getitem__(self, o):
		return self._dict[id(o)][0]
	
	def __delitem__(self, o):
		del self._dict[id(o)]
		if len(self._dict) < 2:
			self._build_heap()
	
	def __len__(self):
		return len(self._dict)
