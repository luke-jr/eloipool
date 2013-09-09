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

from hashlib import sha256
from math import log
import re
import string
from struct import unpack
import traceback

def YN(b):
	if b is None:
		return None
	return 'Y' if b else 'N'

def _maybe_int(n):
	n_int = int(n)
	if n == n_int:
		return n_int
	return n

def target2avghashes(target):
	if target is None:
		return None
	return _maybe_int(target2avghashes._factor / target)
target2avghashes._factor = 2**256

def target2pdiff(target):
	if target is None:
		return None
	pdiff = round(2**(224 - log(target, 2)), 8)
	return _maybe_int(pdiff)

bdiff1target = 0x00000000FFFF0000000000000000000000000000000000000000000000000000

def target2bdiff(target):
	bdiff = bdiff1target / target
	return _maybe_int(bdiff)

class shareLogFormatter:
	_re_x = re.compile(r'^\s*(\w+)\s*(?:\(\s*(.*?)\s*\))?\s*$')
	
	def __init__(self, *a, **ka):
		self._p = self.parse(*a, **ka)
	
	# NOTE: This only works for psf='%s' (default)
	def formatShare(self, *a, **ka):
		(stmt, params) = self.applyToShare(*a, **ka)
		return stmt % params
	
	def applyToShare(self, share):
		(stmt, stmtf) = self._p
		params = []
		for f in stmtf:
			params.append(f(share))
		params = tuple(params)
		return (stmt, params)
	
	@classmethod
	def parse(self, stmt, psf = '%s'):
		fmt = string.Formatter()
		pstmt = tuple(fmt.parse(stmt))
		
		stmt = ''
		fmt = []
		for (lit, field, fmtspec, conv) in pstmt:
			stmt += lit
			if not field:
				continue
			f = self.get_field(field)
			fmt.append(f)
			stmt += psf
		fmt = tuple(fmt)
		return (stmt, fmt)
	
	@classmethod
	def get_field(self, field):
		m = self._re_x.match(field)
		if m:
			if m.group(2) is None:
				# identifier
				return lambda s: s.get(field, None)
			else:
				# function
				fn = m.group(1)
				sf = self.get_field(m.group(2))
				gfm = 'get_field_%s' % (fn,)
				if hasattr(self, gfm):
					return getattr(self, gfm)(sf)
				f = eval(fn)
				return self._get_field_auto(f, sf)
		raise ValueError('Failed to parse field: %s' % (field,))
	
	@classmethod
	def _get_field_auto(self, f, subfunc):
		return lambda s: f(subfunc(s))
	
	@classmethod
	def get_field_not(self, subfunc):
		return lambda s: not subfunc(s)
	
	@classmethod
	def get_field_Q(self, subfunc):
		return lambda s: subfunc(s) or '?'
	
	@classmethod
	def get_field_dash(self, subfunc):
		return lambda s: subfunc(s) or '-'

def dblsha(b):
	return sha256(sha256(b).digest()).digest()

def swap32(b):
	o = b''
	for i in range(0, len(b), 4):
		o += b[i + 3:i - 1 if i else None:-1]
	return o

def Bits2Target(bits):
	return unpack('<L', bits[:3] + b'\0')[0] * 2**(8*(bits[3] - 3))

def LEhash2int(h):
	n = unpack('<QQQQ', h)
	n = (n[3] << 192) | (n[2] << 128) | (n[1] << 64) | n[0]
	return n

def BEhash2int(h):
	n = unpack('>QQQQ', h)
	n = (n[0] << 192) | (n[1] << 128) | (n[2] << 64) | n[3]
	return n

def tryErr(func, *a, **kw):
	IE = kw.pop('IgnoredExceptions', BaseException)
	logger = kw.pop('Logger', None)
	emsg = kw.pop('ErrorMsg', None)
	try:
		return func(*a, **kw)
	except IE:
		if logger:
			emsg = "%s\n" % (emsg,) if emsg else ""
			emsg += traceback.format_exc()
			logger.error(emsg)
		return None

class RejectedShare(ValueError):
	pass

PendingUpstream = object()


import heapq

class ScheduleDict:
	def __init__(self):
		self._dict = {}
		self._build_heap()
	
	def _build_heap(self):
		newheap = list((v[0], id(o), o) for o, v in self._dict.items())
		heapq.heapify(newheap)
		self._heap = newheap
	
	def nextTime(self):
		while True:
			(t, k, o) = self._heap[0]
			if o in self._dict:
				break
			heapq.heappop(self._heap)
		return t
	
	def shift(self):
		while True:
			(t, k, o) = heapq.heappop(self._heap)
			if o in self._dict:
				break
		del self._dict[o]
		return o
	
	def __setitem__(self, o, t):
		k = id(o)
		self._dict[o] = (t, o)
		if len(self._heap) / 2 > len(self._dict):
			self._build_heap()
		else:
			heapq.heappush(self._heap, (t, k, o))
	
	def __contains__(self, o):
		return o in self._dict
	
	def __getitem__(self, o):
		return self._dict[o][0]
	
	def __delitem__(self, o):
		del self._dict[o]
		if len(self._dict) < 2:
			self._build_heap()
	
	def __len__(self):
		return len(self._dict)

class WithNoop:
	def __enter__(self):
		pass
	def __exit__(self, *a):
		pass
WithNoop = WithNoop()


from collections import deque
import threading
import time

class _UniqueSessionIdManager:
	def __init__(self, size = 4, defaultDelay = 120):
		self._NextID = 0
		self._NextID_Lock = threading.Lock()
		self._FreeIDs = deque()
		self._size = size
		self._max = (0x100 ** size) - 1
		self._defaultDelay = defaultDelay
		self._schPut = ScheduleDict()
		self._schPut_Lock = threading.Lock()
	
	def size(self):
		return self._size
	
	def put(self, sid, delay = False, now = None):
		if not delay:
			return self._FreeIDs.append(sid)
		
		if delay is True:
			delay = self._defaultDelay
		if now is None:
			now = time.time()
		with self._schPut_Lock:
			self._schPut[sid] = now + delay
	
	def get(self, desired = None, now = None):
		try:
			return self._FreeIDs.popleft()
		except IndexError:
			pass
		
		# Check delayed-free for one
		if now is None:
			now = time.time()
		with self._schPut_Lock:
			if len(self._schPut) and self._schPut.nextTime() <= now:
				sid = self._schPut.shift()
				while len(self._schPut) and self._schPut.nextTime() <= now:
					self.put(self._schPut.shift())
				return sid
		
		# If none free, make a new one
		with self._NextID_Lock:
			sid = self._NextID
			self._NextID = sid + 1
		if sid <= self._max:
			return sid
		
		# TODO: Maybe steal an about-to-be-freed SID in the worst case scenario?
		
		raise IndexError('Ran out of session ids')
	
	# NOTE: Will steal a pending-free sid
	def getSpecific(self, desired):
		try:
			self._FreeIDs.remove(desired)
			return desired
		except ValueError:
			pass
		
		# FIXME: relies on id(number) == id(number)
		with self._schPut_Lock:
			if desired in self._schPut:
				del self._schPut[desired]
				return desired
		
		# NOTE: Generated growth is limited to avoid memory exhaustion exploits
		with self._NextID_Lock:
			NextID = self._NextID
			if desired >= NextID and desired <= min(self._max, NextID + 0x10000 - len(self._FreeIDs)):
				# NOTE: Incrementing _NextID up front in case of exception
				self._NextID = desired + 1
				for i in range(NextID, desired):
					self.put(i)
				return desired
		
		raise KeyError('Session id %u not available' % (desired,))

UniqueSessionIdManager = _UniqueSessionIdManager()
