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
from struct import unpack

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

class RejectedShare(ValueError):
	pass
