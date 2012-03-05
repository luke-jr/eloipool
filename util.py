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
import re
import string
from struct import unpack
import traceback

def YN(b):
	if b is None:
		return None
	return 'Y' if b else 'N'

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
				return getattr(self, 'get_field_%s' % (fn,))(sf)
		raise ValueError('Failed to parse field: %s' % (field,))
	
	@classmethod
	def get_field_not(self, subfunc):
		return lambda s: not subfunc(s)
	
	@classmethod
	def get_field_Q(self, subfunc):
		return lambda s: subfunc(s) or '?'
	
	@classmethod
	def get_field_dash(self, subfunc):
		return lambda s: subfunc(s) or '-'
	
	@classmethod
	def get_field_YN(self, subfunc):
		return lambda s: YN(subfunc(s))

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


import heapq

class ScheduleDict:
	def __init__(self):
		self._dict = {}
		self._build_heap()
	
	def _build_heap(self):
		newheap = list((v[0], k, v[1]) for k, v in self._dict.items())
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
