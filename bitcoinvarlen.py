from struct import pack, unpack

_ignoredrc = [0]

def varlenDecode(b, rc = _ignoredrc):
	if b[0] == b'\xff':
		rc[0] += 9
		return (unpack('<Q', b[1:9])[0], b[9:])
	if b[0] == b'\xfe':
		rc[0] += 5
		return (unpack('<L', b[1:5])[0], b[5:])
	if b[0] == b'\xfd':
		rc[0] += 3
		return (unpack('<H', b[1:3])[0], b[3:])
	rc[0] += 1
	return (b[0], b[1:])

def varlenEncode(n):
	if n < 0xfd:
		return pack('<B', n)
	if n < 0xffff:
		return '\xfd' + pack('<H', n)
	if n < 0xffffffff:
		return '\xfe' + pack('<L', n)
	return pack('<Q', n)
