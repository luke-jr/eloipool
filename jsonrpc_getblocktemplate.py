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
from copy import deepcopy
from jsonrpcserver import JSONRPCHandler
from time import time
from util import RejectedShare

_NoParams = {}

class _getblocktemplate:
	def final_init(server):
		ShareTargetHex = '%064x' % (server.ShareTarget,)
		JSONRPCHandler.getblocktemplate_rv_template['target'] = ShareTargetHex
	
	getblocktemplate_rv_template = {
		'longpoll': '/LP',
		'mutable': [
			'coinbase/append',
			'submit/coinbase',
		],
		'noncerange': '00000000ffffffff',
		'target': '00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
		'expires': 120,
		'version': 3,
		'submitold': True,
		
		# Bitcoin-specific:
		'sigoplimit': 20000,
		'sizelimit': 1000000,
	}
	def doJSON_getblocktemplate(self, params):
		if 'mode' in params and params['mode'] != 'template':
			raise AttributeError('getblocktemplate mode "%s" not supported' % (params['mode'],))
		
		if 'longpollid' in params:
			self.processLP(params['longpollid'])
		
		RequestedTarget = None
		try:
			RequestedTarget = int(params['target'], 16)
		except:
			pass
		
		rv = dict(self.getblocktemplate_rv_template)
		p_magic = [False]
		(MC, wld, target) = self.server.getBlockTemplate(self.Username, p_magic=p_magic, RequestedTarget=RequestedTarget)
		(height, merkleTree, cb, prevBlock, bits) = MC[:5]
		rv['height'] = height
		rv['previousblockhash'] = b2a_hex(prevBlock[::-1]).decode('ascii')
		if p_magic[0]:
			rv['longpollid'] = 'bootstrap'
		else:
			rv['longpollid'] = str(self.server.LPId)
		tl = []
		for txn in merkleTree.data[1:]:
			txno = {}
			txno['data'] = b2a_hex(txn.data).decode('ascii')
			tl.append(txno)
		rv['transactions'] = tl
		now = int(time())
		rv['time'] = now
		# FIXME: ensure mintime is always >= real mintime, both here and in share acceptance
		rv['mintime'] = now - 180
		rv['curtime'] = now
		rv['maxtime'] = now + 120
		rv['bits'] = b2a_hex(bits[::-1]).decode('ascii')
		rv['target'] = '%064x' % (target,)
		t = deepcopy(merkleTree.data[0])
		t.setCoinbase(cb)
		t.assemble()
		txno = {}
		txno['data'] = b2a_hex(t.data).decode('ascii')
		rv['coinbasetxn'] = txno
		return rv
	
	def doJSON_submitblock(self, data, params = _NoParams):
		data = bytes.fromhex(data)
		share = {
			'data': data[:80],
			'blkdata': data[80:],
			'username': self.Username,
			'remoteHost': self.remoteHost,
		}
		try:
			self.server.receiveShare(share)
		except RejectedShare as rej:
			return str(rej)
		return None

JSONRPCHandler._register(_getblocktemplate)
