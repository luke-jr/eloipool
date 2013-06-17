# Eloipool - Python Bitcoin pool server
# Copyright (C) 2011-2013  Luke Dashjr <luke-jr+eloipool@utopios.org>
# Written by Peter Leurs <kinlo@triplemining.com>
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
import threading
import traceback
from time import sleep
import os

_logger = logging.getLogger('authentication.simplefile')

class simplefile(threading.Thread):
        def __init__(self, filename, **ka):
            super().__init__(**ka.get('thropts', {}))
            self.fn=filename
            self.userdb = dict()
            self.lastmodified = os.path.getmtime(self.fn)
            self.reloadDb()
            self.start()

        def run(self):
            while True:
                try:
                        sleep(0.2)
                        if self.lastmodified!=os.path.getmtime(self.fn):
                                self.lastmodified = os.path.getmtime(self.fn)
                                sleep(0.2)
                                self.reloadDb()
                except:
                        _logger.critical(traceback.format_exc())

        def reloadDb(self):
            try:
                newdb = dict()
                fh = open(self.fn, "rb")
                data = fh.read()
                for line in data.split(b'\n'):
                        (user, passwd) = line.split(b'\t')
                        newdb[user.decode('utf8')]=passwd.decode('utf8')
                self.userdb = newdb
                _logger.info("Reloaded user db")
            except:
                _logger.critical("fatal error reading userdatabase: %s", traceback.format_exc())

        def checkAuthentication(self, user, password):
                if user not in self.userdb:
                        return False
                if self.userdb[user] == password:
                        return True
                return False


