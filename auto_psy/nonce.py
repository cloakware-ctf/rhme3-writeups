def nswap(c):
    return (c>>4) | (c<<4 & 0xf0)

def bswap(short):
    return (short>>8) | (short<<8 & 0xff00)

Carry = 0
def lsr(byte):
    global Carry
    Carry = byte&1
    return byte >> 1

def ror(byte):
    global Carry
    oldcarry = Carry
    Carry = byte&1
    return (byte >> 1) | (oldcarry << 7)

def sub_460(rx24, r22):
    r24 = rx24 & 0xff
    r25 = rx24 >> 8

    r24 ^= r22
    r22 = r24
    r22 = nswap(r22)
    r22 ^= r24
    r0 = r22
    r22 = lsr(r22)
    r22 = lsr(r22)
    r22 ^= r0
    r0 = r22
    r22 = lsr(r22)
    r22 ^= r0
    r22 &= 7

    r0 = r24
    r24 = r25
    r22 = lsr(r22)
    r0 = ror(r0)
    r22 = ror(r22)
    r25 = r0
    r24 ^= r22
    r0 = lsr(r0)
    r22 = ror(r22)
    r25 ^= r0
    r24 ^= r22
    return r25 << 8 | r24

def check_key_4b8(arg0, arg1):
    # returns 0x0000 to indicate success
    rY = [0x45, 0x71, 0x3D, 0x8B, 0x4F]
    rx24 = 0
    for y in rY:
        rx24 = sub_460(rx24, y)
    rx24 = sub_460(rx24, arg0>>8)
    rx24 = sub_460(rx24, arg0&0xff)

    # check arg1 against output
    #puts "#{rx24.to_s(16)} vs #{arg1.to_s(16)}"
    #puts "#{(rx24>>8).to_s(16)} vs #{(arg1>>8).to_s(16)}"
    if (rx24>>8 != arg1>>8):
        return 0x0002 # fail

    if (rx24 == 0x0000):
        r19 = 1 # probably 1
    else:
        r19 = 0

    if (arg1 != 0x0000):
        r18 = 1 # probably 0
    else:
        r18 = 0

    if (r18 == r19):
        return 0x0001 # fail
    else:
        return 0x0000 # success

def test_check_key_4b8(arg0, arg1):
    if (0 == check_key_4b8(arg0, arg1)):
        print("Test Success")
    else:
        print("FAILURE")

if __name__ == "__main__":
    test_check_key_4b8(0x98e5, 0x989f)
    test_check_key_4b8(0xf1bc, 0xf287)
    test_check_key_4b8(0x850b, 0x840a)
    test_check_key_4b8(0xe859, 0xe963)

