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
		return b'\x76\xa9\x14' + pubkeyhash + b'\x88\xac'

def countSigOps(s):
	# FIXME: don't count data as ops
	c = 0
	for ch in s:
		if 0xac == ch & 0xfe:
			c += 1
		elif 0xae == ch & 0xfe:
			c += 20
	return c
