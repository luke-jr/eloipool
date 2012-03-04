# Eloipool - Python Bitcoin pool server
# Copyright (C) 2011-2012  Luke Dashjr <luke-jr+eloipool@utopios.org>
# Copyright (C) 2012  Peter Leurs <kinlo@triplemining.com>
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



from collections import deque
from datetime import date
from time import sleep, time
import threading
from util import YN
import logging
import traceback

_logger = logging.getLogger('logshares_files')

class _writeshares(threading.Thread):
	def __init__(self, filename, *a, **k):
		super().__init__(*a, **k)
		self.fn=filename
		self.queue = deque()
	
	def queueshare(self, line):
		self.queue.append(line)
	
	def flushlog(self):
		if len(self.queue) > 0:
			with open(self.fn, "a") as logfile:
				while len(self.queue)>0:
					logfile.write(self.queue.popleft())
	
	def run(self):
		while True:
			try:
				sleep(0.2)
				self.flushlog()
			except:
				_logger.critical(traceback.format_exc())

sharewriter = None

def setup(filename):
	global sharewriter
	sharewriter = _writeshares(filename)
	sharewriter.start()

def logShare(share):
	global sharewriter
	timestamp = time()
	address = share.get('remoteHost','?')
	username = share['username']
	ourresult = YN(not share.get('rejectReason', None))
	upstreamresult = YN(share.get('upstreamResult', None))
	reason = share.get('rejectReason','-')
	solution = share['solution']
	
	logline = "{} {} {} {} {} {} {}\n".format(timestamp, address, username, ourresult, upstreamresult, reason, solution)
	sharewriter.queueshare(logline)


