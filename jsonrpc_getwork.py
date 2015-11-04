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

from binascii import b2a_hex
from jsonrpcserver import JSONRPCHandler
import logging
from struct import pack
from util import RejectedShare, swap32

_CheckForDupesHACK = {}
_RealDupes = {}
class _getwork:
	def final_init(server):
		ShareTargetHex = '%064x' % (server.ShareTarget,)
		ShareTargetHexLE = b2a_hex(bytes.fromhex(ShareTargetHex)[::-1]).decode('ascii')
		JSONRPCHandler.getwork_rv_template['target'] = ShareTargetHexLE
	
	getwork_rv_template = {
		'data': '000000800000000000000000000000000000000000000000000000000000000000000000000000000000000080020000',
		'target': 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffff00000000',
		'hash1': '00000000000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000010000',
		'submitold': True,
	}
	def doJSON_getwork(self, data=None):
		if not data is None:
			return self.doJSON_submitwork(data)
		rv = dict(self.getwork_rv_template)
		(hdr, x, target) = self.server.getBlockHeader(self.Username)
		
		# FIXME: this assumption breaks with internal rollntime
		# NOTE: noncerange needs to set nonce to start value at least
		global _CheckForDupesHACK
		uhdr = hdr[:68] + hdr[72:]
		if uhdr in _CheckForDupesHACK:
			_RealDupes[uhdr] = (_CheckForDupesHACK[uhdr], (hdr, x))
			raise self.server.RaiseRedFlags(RuntimeError('issuing duplicate work'))
		_CheckForDupesHACK[uhdr] = (hdr, x)
		
		data = b2a_hex(swap32(hdr)).decode('utf8') + rv['data']
		# TODO: endian shuffle etc
		rv['data'] = data
		if midstate and 'midstate' not in self.extensions and 'midstate' not in self.quirks:
			h = midstate.SHA256(hdr)[:8]
			rv['midstate'] = b2a_hex(pack('<LLLLLLLL', *h)).decode('ascii')
		
		ShareTargetHex = '%064x' % (target,)
		ShareTargetHexLE = b2a_hex(bytes.fromhex(ShareTargetHex)[::-1]).decode('ascii')
		rv['target'] = ShareTargetHexLE
		
		self._JSONHeaders['X-Roll-NTime'] = 'expire=120'
		
		return rv
	
	def doJSON_submitwork(self, datax):
		data = swap32(bytes.fromhex(datax))[:80]
		share = {
			'data': data,
			'_origdata' : datax,
			'username': self.Username,
			'remoteHost': self.remoteHost,
			'userAgent': self.UA,
			'submitProtocol': 'getwork',
		}
		try:
			self.server.receiveShare(share)
		except RejectedShare as rej:
			self._JSONHeaders['X-Reject-Reason'] = str(rej)
			return False
		return True

JSONRPCHandler._register(_getwork)
