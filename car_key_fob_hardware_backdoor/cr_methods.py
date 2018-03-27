import bitstring
import hmac
import hashlib
from Crypto.Cipher import AES


def pad_out(sequence, target_bit_length):
   output = sequence.copy()
   padding_size_needed = target_bit_length - output.len
   output.append(bitstring.BitString(bin='0'*padding_size_needed))
   return output

from Crypto.Cipher import AES
def encrypt(cipher, clear_sequence):
   response_sequence = bitstring.BitString(cipher.encrypt(clear_sequence.tobytes()))
   return response_sequence

def decrypt(cipher, cipher_sequence):
   response_sequence = bitstring.BitString(cipher.decrypt(cipher_sequence.tobytes()))
   return response_sequence

def aes_ecb(key_sequence):
   return AES.new(key_sequence.tobytes(), AES.MODE_ECB)

def aes_cbc(key_sequence):
   return AES.new(key_sequence.tobytes(), AES.MODE_CBC, IV=bitstring.BitString(bin='0'*128).tobytes())

def aes_ctr(key_sequence):
   def trivial():
      return bitstring.BitString(bin='0'*128).tobytes()

   return AES.new(key_sequence.tobytes(), AES.MODE_CTR, counter=trivial)

################################################################################
# Password Preparations

def trivial(sequence):
   return sequence

def pad_password(password_sequence):
   return pad_out(password_sequence, 128)

def md5_password(password_sequence):
   return bitstring.BitString(hex=hashlib.md5(password_sequence.tobytes()).hexdigest())

def ssl_password(password_sequence):
  return bitstring.BitString(hex=hashlib.sha256(password_sequence.tobytes()).hexdigest())[:128]

#################################################################################
# Message Responders

def get_cipher_message_responder(cipher_operation, cipher):
   def cipher_message_responder(key_sequence, challenge_sequence):
      if key_sequence.len != 128 or challenge_sequence.len != 128:
         raise ValueError("only 128bit sequences supported. %d, %d" % (key_sequence.len, challenge_sequence.len))
      return cipher_operation(cipher(key_sequence), challenge_sequence)
   return cipher_message_responder

def hmacmd5(key, message):
   return bitstring.BitString(hex=hmac.new(key.tobytes(), message.tobytes(), digestmod=hashlib.md5).hexdigest())

def md5concat(password_sequence, challenge_sequence):
   input_sequence = challenge_sequence.copy()
   input_sequence.append(password_sequence)
   return bitstring.BitString(hex=hashlib.md5(input_sequence.tobytes()).hexdigest())

def xor(password_sequence, challenge_sequence):
  response_sequence = challenge_sequence ^ password_sequence
  return response_sequence

##################################################################################
# Message Responder Modifiers

def get_trivial_responder(message_responder):
   return message_responder

def get_rev_responder(message_responder):
   def rev_responder(password_sequence, challenge_sequence):
      challenge_sequence = challenge_sequence.copy()
      challenge_sequence.reverse()
      response_sequence = message_responder(password_sequence, challenge_sequence)
      response_sequence = response_sequence[:128]
      response_sequence.reverse()
      response_sequence.overwrite(response_sequence, 0)
      return response_sequence
   return rev_responder

def get_swp_responder(message_responder):
   def swp_responder(password_sequence, challenge_sequence):
      response_sequence = message_responder(challenge_sequence[:128], password_sequence)
      return response_sequence
   return swp_responder

def get_swprev_responder(message_responder):
 def swprev_responder(password_sequence, challenge_sequence):
   challenge_sequence = challenge_sequence.copy()
   challenge_sequence.reverse()
   response_sequence = message_responder(challenge_sequence[:128], password_sequence)
   response_sequence = response_sequence[:128]
   response_sequence.reverse()
   response_sequence.overwrite(response_sequence, 0)
   return response_sequence
 return swprev_responder

def bitswap(input_sequence):
  input_sequence = input_sequence.copy()
  for pos in range(0, input_sequence.len, 8):
    byte_sequence = input_sequence[pos:pos+8]
    byte_sequence.reverse()
    input_sequence.overwrite(byte_sequence, pos)
  return input_sequence

def get_bitswapped_responder(message_responder):
  def bitswapped_responder(password_sequence, challenge_sequence):
    challenge_sequence = bitswap(challenge_sequence)
    response_sequence = message_responder(password_sequence, challenge_sequence[:128])
    response_sequence.overwrite(bitswap(response_sequence[:128]),0)
    return response_sequence
  return bitswapped_responder

def get_rev_bitswapped_responder(message_responder):
  def rev_bitswapped_responder(password_sequence, challenge_sequence):
    challenge_sequence = challenge_sequence.copy()
    challenge_sequence.reverse()
    challenge_sequence = bitswap(challenge_sequence)
    response_sequence = message_responder(password_sequence, challenge_sequence)
    response_sequence = bitswap(response_sequence[:128])
    response_sequence.reverse()
    response_sequence.overwrite(response_sequence, 0)
    return response_sequence
  return rev_bitswapped_responder


