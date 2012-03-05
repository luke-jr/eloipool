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

import logging
from util import shareLogFormatter

_logger = logging.getLogger('sharelogging.sql')

class sql:
	_psf = {
		'qmark': '?',
		'format': '%s',
	}
	
	def __init__(self, **ka):
		self.opts = ka
		dbe = ka['engine']
		if 'statement' not in ka:
			_logger.warn('"statement" not specified for sql logger, but default may vary!')
		getattr(self, 'setup_%s' % (dbe,))()
	
	def setup_postgres(self, **ka):
		import psycopg2
		self.db = psycopg2.connect(**self.opts.get('dbopts', {}))
		ka.setdefault('statement', "insert into shares (rem_host, username, our_result, upstream_result, reason, solution) values ({Q(remoteHost)}, {username}, {YN(not(rejectReason))}, {YN(upstreamResult)}, {rejectReason}, decode({solution}, 'hex'))")
		self.modsetup(psycopg2)
	
	def modsetup(self, mod):
		psf = self._psf[mod.paramstyle]
		stmt = self.opts['statement']
		self.pstmt = shareLogFormatter(stmt, psf)
	
	def logShare(self, share):
		(stmt, params) = self.pstmt.applyToShare(share)
		dbc = self.db.cursor()
		dbc.execute(stmt, params)
		self.db.commit()
