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

def exit():
	import os, signal
	os.kill(os.getpid(), signal.SIGTERM)

def _RunCLI():
	import code, sys, threading
	try:
		raise None
	except:
		namespace = sys.exc_info()[2].tb_frame.f_back.f_back.f_globals
	
	namespace.setdefault('exit', exit)
	
	def CLI():
		while True:
			code.interact(local=namespace, banner='')
			print("Not exiting implicitly. Use exit() if you really want to.")
			dt = ndt = 0
			for thread in threading.enumerate():
				if thread.daemon:
					dt += 1
				else:
					ndt += 1
			print("(%d threads: %d primary, %d daemon)" % (dt + ndt, ndt, dt))
	threading.Timer(0, CLI).start()

_RunCLI()
