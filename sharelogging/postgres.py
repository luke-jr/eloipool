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

import psycopg2
from util import YN

class postgres:
	def __init__(self, *a, **ka):
		self.db = psycopg2.connect(*a, **ka)
	
	def logShare(self, share):
		dbc = self.db.cursor()
		rem_host = share.get('remoteHost', '?')
		username = share['username']
		reason = share.get('rejectReason', None)
		upstreamResult = share.get('upstreamResult', None)
		solution = share['solution']
		stmt = "insert into shares (rem_host, username, our_result, upstream_result, reason, solution) values (%s, %s, %s, %s, %s, decode(%s, 'hex'))"
		params = (rem_host, username, YN(not reason), YN(upstreamResult), reason, solution)
		dbc.execute(stmt, params)
		self.db.commit()
