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
from queue import Queue
import threading
import traceback
from util import shareLogFormatter

_logger = logging.getLogger('sharelogging.sql')

class sql:
	_psf = {
		'qmark': '?',
		'format': '%s',
		'pyformat': '%s',
	}
	
	def __init__(self, **ka):
		self.opts = ka
		dbe = ka['engine']
		if 'statement' not in ka:
			_logger.warn('"statement" not specified for sql logger, but default may vary!')
		self.threadsafe = False
		getattr(self, 'setup_%s' % (dbe,))()
		if self.threadsafe:
			self._logShareF = self._doInsert
			self.stop = self._shutdown
			self._connect()
		else:
			self._queue = Queue()
			self._logShareF = self._queue.put
			threading.Thread(target=self._thread).start()
	
	def _doInsert(self, o):
		(stmt, params) = o
		dbc = self.db.cursor()
		dbc.execute(stmt, params)
		self.db.commit()
	
	def _thread(self):
		self._connect()
		while True:
			try:
				o = self._queue.get()
				if o is None:
					# Shutdown logger
					break
				self._doInsert(o)
			except:
				_logger.critical(traceback.format_exc())
		self._shutdown()
	
	def setup_mysql(self):
		import pymysql
		dbopts = self.opts.get('dbopts', {})
		if 'passwd' not in dbopts and 'password' in dbopts:
			dbopts['passwd'] = dbopts['password']
			del dbopts['password']
		self.modsetup(pymysql)
	
	def setup_postgres(self):
		import psycopg2
		self.opts.setdefault('statement', "insert into shares (rem_host, username, our_result, upstream_result, reason, solution) values ({Q(remoteHost)}, {username}, {YN(not(rejectReason))}, {YN(upstreamResult)}, {rejectReason}, decode({solution}, 'hex'))")
		self.modsetup(psycopg2)
	
	def setup_sqlite(self):
		import sqlite3
		self.modsetup(sqlite3)
	
	def modsetup(self, mod):
		self._mod = mod
		psf = self._psf[mod.paramstyle]
		self.opts.setdefault('statement', "insert into shares (remoteHost, username, rejectReason, upstreamResult, solution) values ({remoteHost}, {username}, {rejectReason}, {upstreamResult}, {solution})")
		stmt = self.opts['statement']
		self.pstmt = shareLogFormatter(stmt, psf)
	
	def _connect(self):
		self.db = self._mod.connect(**self.opts.get('dbopts', {}))
	
	def logShare(self, share):
		o = self.pstmt.applyToShare(share)
		self._logShareF(o)
	
	def stop(self):
		# NOTE: this is replaced with _shutdown directly for threadsafe objects
		self._queue.put(None)
	
	def _shutdown(self):
		pass # TODO
