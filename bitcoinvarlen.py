from struct import pack, unpack

def varlenDecode(b):
	if b[0] == 0xff:
		return (unpack('<Q', b[1:9])[0], b[9:])
	if b[0] == 0xfe:
		return (unpack('<L', b[1:5])[0], b[5:])
	if b[0] == 0xfd:
		return (unpack('<H', b[1:3])[0], b[3:])
	return (b[0], b[1:])

def varlenEncode(n):
	if n < 0xfd:
		return pack('<B', n)
	if n <= 0xffff:
		return b'\xfd' + pack('<H', n)
	if n <= 0xffffffff:
		return b'\xfe' + pack('<L', n)
	return b'\xff' + pack('<Q', n)

# tests
def _test():
	assert b'\0' == varlenEncode(0)
	assert b'\xfc' == varlenEncode(0xfc)
	assert b'\xfd\xfd\0' == varlenEncode(0xfd)
	assert b'\xfd\xff\xff' == varlenEncode(0xffff)
	assert b'\xfe\0\0\1\0' == varlenEncode(0x10000)
	assert b'\xfe\xff\xff\xff\xff' == varlenEncode(0xffffffff)
	assert b'\xff\0\0\0\0\1\0\0\0' == varlenEncode(0x100000000)
	assert b'\xff\xff\xff\xff\xff\xff\xff\xff\xff' == varlenEncode(0xffffffffffffffff)

_test()
