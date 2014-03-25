# Eloipool - Python Bitcoin pool server
# Copyright (C) 2012-2014  Luke Dashjr <luke-jr+eloipool@utopios.org>
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
import os
import stat

# It is not legal to bypass or lie to this check. See LICENSE file for details.
try:
	_srcdir = os.path.dirname(os.path.abspath(__file__))
	if os.path.exists(_srcdir + '/.I_swear_that_I_am_Luke_Dashjr'):
		_SourceFiles = None
	else:
		_SourceFiles = os.popen('cd \'%s\' && git ls-files' % (_srcdir,)).read().split('\n')
		try:
			_SourceFiles.remove('')
		except ValueError:
			pass
		if len(_SourceFiles) < 2:
			raise RuntimeError('Unknown error')
		_SourceFiles = tuple(x.encode('utf8') for x in _SourceFiles)
		_GitDesc = os.popen('cd \'%s\' && git describe --dirty --always' % (_srcdir,)).read().strip().encode('utf8')
except BaseException as e:
	logging.getLogger('Licensing').critical('Error getting list of source files! AGPL requires this. To fix, be sure you are using git for Eloipool.\n' + traceback.format_exc())
	import sys
	sys.exit(1)

# For AGPL compliance, allow direct downloads of source code
def get_source(p):
	if _SourceFiles is None:
		return None
	if p == b'':
		# List of files
		body = b'<html><head><title>Source Code</title></head><body>\t\n'
		body += b'\t<a href="tar">(tar archive of all files)</a><br><br>\n'
		for f in _SourceFiles:
			body += b'\t<a href="' + f + b'">\n' + f + b'\n\t</a><br>\n'
		body += b'\t</body></html>\n'
		return ('text/html', body)
	if p == b'tar':
		body = bytearray()
		dn = b'eloipool-' + _GitDesc + b'/'
		for f in _SourceFiles:
			fs = f.decode('utf8')
			fstat = os.lstat(fs)
			islink = stat.S_ISLNK(fstat.st_mode)
			if islink:
				data = b''
				link = os.readlink(f)
			else:
				with open("%s/%s" % (_srcdir, fs), 'rb') as ff:
					data = ff.read()
				link = b''
			h = bytearray()
			f = dn + f
			h += f + bytes(max(0, 100 - len(f)))
			h += ('%07o' % (fstat.st_mode,)[-7:]).encode('utf8') + b'\0'
			h += bytes(16)
			h += ('%012o%012o' % (fstat.st_size, fstat.st_mtime)).encode('utf8')
			h += b'        '  # chksum
			h += b'2' if islink else b'0'
			h += link + bytes(max(0, 355 - len(link)))
			h[148:156] = ('%07o' % (sum(h),)).encode('utf8') + b'\0'
			body += h + data + bytes(512 - ((fstat.st_size % 512) or 512))
		return ('application/x-tar', body)
	if p not in _SourceFiles:
		return None
	ct = 'text/plain'
	if p[-3:] == b'.py': ct = 'application/x-python'
	elif p[-11:] == b'.py.example': ct = 'application/x-python'
	p = p.decode('utf8')
	with open("%s/%s" % (_srcdir, p), 'rb') as f:
		return (ct, f.read())
