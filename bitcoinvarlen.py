from struct import unpack

def varlenDecode(b):
	if b[0] == b'\xff':
		return (unpack('<Q', b[1:9]), b[9:])
	if b[0] == b'\xfe':
		return (unpack('<L', b[1:5]), b[5:])
	if b[0] == b'\xfd':
		return (unpack('<H', b[1:3]), b[3:])
	return (unpack('<B', b[0]), b[1:])

def varlenEncode(n):
	if n < 0xfd:
		return pack('<B', n)
	if n < 0xffff:
		return '\xfd' + pack('<H', n)
	if n < 0xffffffff:
		return '\xfe' + pack('<L', n)
	return pack('<Q', n)
