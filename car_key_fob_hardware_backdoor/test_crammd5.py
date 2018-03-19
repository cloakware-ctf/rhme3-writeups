import sys
import bitstring
import hmac
import hashlib

bitstring.bytealigned = True     # change the default behaviour

challenge = bitstring.BitString(hex='1d1f7ebfc4bc987fa304ebd3df35a98d')
password = bitstring.BitString(b'password')
password_digest = bitstring.BitString(hex=hashlib.md5(password.tobytes()).hexdigest())
expected = bitstring.BitString(hex='cd70f14cae8f8e195b1d28e8824111e5')

response = bitstring.BitString(hex=hmac.new(password.tobytes(), challenge.tobytes(), digestmod=hashlib.md5).hexdigest())

print("chall:    %s" % challenge.hex)
print("passwd:   %s" % password_digest.hex)
print("expected: %s" % expected.hex)
print("response: %s" % response.hex)
