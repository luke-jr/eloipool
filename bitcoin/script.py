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

from base58 import b58decode
from util import dblsha

WitnessMagic = b'\xaa\x21\xa9\xed'

def _Address2PKH(addr):
	try:
		addr = b58decode(addr, 25)
	except:
		return None
	if addr is None:
		return None
	ver = addr[0]
	cksumA = addr[-4:]
	cksumB = dblsha(addr[:-4])[:4]
	if cksumA != cksumB:
		return None
	return (ver, addr[1:-4])

class BitcoinScript:
	@classmethod
	def toAddress(cls, addr):
		d = _Address2PKH(addr)
		if not d:
			raise ValueError('invalid address')
		(ver, pubkeyhash) = d
		if ver == 0 or ver == 111:
			return b'\x76\xa9\x14' + pubkeyhash + b'\x88\xac'
		elif ver == 5 or ver == 196:
			return b'\xa9\x14' + pubkeyhash + b'\x87'
		raise ValueError('invalid address version')
	
	@classmethod
	def commitment(cls, commitment):
		clen = len(commitment)
		if clen > 0x4b:
			raise NotImplementedError
		return b'\x6a' + bytes((clen,)) + commitment

def countSigOps(s):
	# FIXME: don't count data as ops
	c = 0
	for ch in s:
		if 0xac == ch & 0xfe:
			c += 1
		elif 0xae == ch & 0xfe:
			c += 20
	return c

# NOTE: This does not work for signed numbers (set the high bit) or zero (use b'\0')
def encodeUNum(n):
	s = bytearray(b'\1')
	while n > 127:
		s[0] += 1
		s.append(n % 256)
		n //= 256
	s.append(n)
	return bytes(s)

def encodeNum(n):
	if n == 0:
		return b'\0'
	if n > 0:
		return encodeUNum(n)
	s = encodeUNum(abs(n))
	s = bytearray(s)
	s[-1] = s[-1] | 0x80
	return bytes(s)

# tests
def _test():
	assert b'\0' == encodeNum(0)
	assert b'\1\x55' == encodeNum(0x55)
	assert b'\2\xfd\0' == encodeNum(0xfd)
	assert b'\3\xff\xff\0' == encodeNum(0xffff)
	assert b'\3\0\0\x01' == encodeNum(0x10000)
	assert b'\5\xff\xff\xff\xff\0' == encodeNum(0xffffffff)

_test()
