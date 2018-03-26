#!/usr/bin/env python3

# deps can be satisfied on Linux with `sudo pip3 install pyftdi`

from pyftdi.gpio import GpioController, GpioException
from time import sleep
import sys
import serial
import bitstring
import hmac
import hashlib

bitstring.bytealigned = True     # change the default behaviour

bitbang = GpioController()
bitbang.open_from_url('ftdi:///1')

ser = serial.Serial('/dev/ttyUSB0', 115200, timeout=None)

SOFT_DELAY = 0.00001 #strict worst-case delay is 0.54ms -- we can relax that due to lots of delays in the many layers of software between us.
                 #on my machine this results in a minimum CLK pulse width of 0.69 ms on my machine
HARD_DELAY = 0.00054 # for cases where strict delay adherence is necessary (e.g. when begining shift-out)
DELAY = SOFT_DELAY

state = 0

def pin_output(line):
    bitbang.set_direction(1 << line, 1 << line)
    return

def pin_input(line):
    bitbang.set_direction(1 << line, 0)
    return

def pin_high(line):
    global state
    state = state | (1 << line)
    bitbang.write_port(state)
    return

def pin_low(line):
    global state
    state = state & ~(1 << line)
    bitbang.write_port(state)
    return

def set_pin(line, val):
    if val:
        pin_high(line)
    else:
        pin_low(line)

def get_pin(line):
    state = bitbang.read_port()
    return bool(state & (1 << line))

# SPI Name | MPSSE # | MPSSE Color | RHME3 Pin | Function Guess
CLK        = 0       # ORANGE      | A2        | CLK
MOSI       = 1       # YELLOW      | A4        | DI
MISO       = 2       # GREEN       | A5        | DO
CS         = 3       # BROWN       | A3        | LATCH
RESET      = 4       # GREY        | RESET     | RESET
TRIG_OUT   = 5       # PURPLE      | N/A       | use this to trigger captures externally (e.g. CW)

def shift_in_and_out_byte(tx):
    building_byte = 0
    for i in range(0, 8):
        pin_low(CLK)
        #assuming MSB first for now
        set_pin(MOSI, bool(tx & (1 << (7 - i))))
        sleep(DELAY)

        pin_high(CLK)
        sleep(DELAY)
        building_byte = building_byte | (get_pin(MISO) << (7 - i))

    pin_low(CLK)
    return building_byte

pin_high(RESET)
pin_output(RESET)
pin_low(RESET)

pin_low(CLK)
pin_output(CLK)

pin_low(CS)
pin_output(CS)

pin_high(MOSI)
pin_output(MOSI)

pin_input(MISO)

pin_high(TRIG_OUT)
pin_output(TRIG_OUT)

def log(message):
   print(message)
   with open('send_many_responses.log', 'a') as log_file:
      log_file.write(str(message))
      log_file.write('\n')
   return

def release_reset_and_wait():
    global ser
    log("Resetting Target...")
    pin_low(RESET)
    sleep(2 * HARD_DELAY)
    pin_high(RESET)
    while True:
       line = ser.readline()
       log(line)
       if 'Test mode activated' in line.decode("utf-8"):
          return
    return

release_reset_and_wait()

def get_any_serial():
    global ser
    count = ser.in_waiting
    if count > 0:
        return ser.readline()
    return ''

def print_any_serial():
   line = get_any_serial()
   if not line == '':
      log(line)
      sys.stdout.flush()
   return

blanksss = bitstring.BitString(hex='00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000')
sentinel = bitstring.BitString(hex='cafeabad1deadeadbeefdefea7edd00dcafeabad1deadeadbeefdefea7edd00dcafeabad1deadeadbeefdefea7edd00dcafeabad1deadeadbeefdefea7edd00d')
onesssss = bitstring.BitString(hex='ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff')
#                                   AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD
ro_bits  = bitstring.BitString(hex='000000000000000000000000000000000000350500000000286e00000c05000000000000000000000000000020001e3000000000055500000000000000000000')
instigat = bitstring.BitString(hex='00000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000')
sd_alone = bitstring.BitString(hex='00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000000000000000')
sd_count = bitstring.BitString(hex='00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000')
#                                   fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe000000

def test_shift_depth():
  MAX_DEPTH = 8192

  def test_miso_goes_high():
    for i in range(0, MAX_DEPTH):
      pin_high(CLK)
      sleep(DELAY)
      if get_pin(MISO):
        log("MISO high on count %d, clk-rising" % i)
        break

      pin_low(CLK)
      sleep(DELAY)
      if get_pin(MISO):
        log("MISO high on count %s, clk-falling" % i)
        break

    if not get_pin(MISO):
      log("MISO did not change state to high after %d CLKs" % MAX_DEPTH)

    return

  def test_miso_goes_low():
    pin_low(MOSI)
    for i in range(0, MAX_DEPTH):
      pin_high(CLK)
      sleep(DELAY)
      if not get_pin(MISO):
        log("MISO low on count %d, clk-rising" % i)
        break

      pin_low(CLK)
      sleep(DELAY)
      if not get_pin(MISO):
        log("MISO low on count %s, clk-falling" % i)
        break

    if get_pin(MISO):
      log("MISO did not change state to low after %d CLKs" % MAX_DEPTH)

    return

  if get_pin(MISO):
    test_miso_goes_low()
    test_miso_goes_high()
  else:
    test_miso_goes_high()
    test_miso_goes_low()

  return

def print_a_sequence(sequence):
  log(bitstring.BitString(sequence).hex)
  return

def enable_shift():
  pin_high(CS)
  sleep(HARD_DELAY)
  return

def disable_shift():
  pin_low(CS)
  sleep(HARD_DELAY)
  return

def single_clk_pulse():
  pin_high(CLK)
  sleep(HARD_DELAY)
  pin_low(CLK)
  sleep(HARD_DELAY)
  return

def clock_in_clock_out(first_input_sequence, second_input_sequence, inter_frame_action, unexpected_output_action, serial_handler):
  enable_shift()

  output_sequence = bytearray()
  for i in range(0, int(512 / 8)):
    rx = shift_in_and_out_byte(first_input_sequence.tobytes()[i])
    output_sequence.append(rx)

  line = get_any_serial()
  if not line == '':
    if serial_handler(line):
      log("FAIL: serial message on test-sequence:")
      print_a_sequence(first_input_sequence.tobytes())
      log("")
      return None

  disable_shift()

  if unexpected_output_action(output_sequence):
    log("FAIL: unexpected output:")
    print_a_sequence(output_sequence)
    log("")

  inter_frame_action()

  line = get_any_serial()
  if not line == '':
    if serial_handler(line):
      log("FAIL: serial message on test-sequence:")
      print_a_sequence(first_input_sequence.tobytes())
      log("\n")
      return None

  enable_shift()

  output_sequence = bytearray()
  for i in range(0, int(512 / 8)):
    rx = shift_in_and_out_byte(second_input_sequence.tobytes()[i])
    output_sequence.append(rx)

  line = get_any_serial()
  if not line == '':
    if serial_handler(line):
      log("FAIL: serial message. first input sequence:")
      print_a_sequence(first_input_sequence.tobytes())
      log("")
      return None

  disable_shift()

  if unexpected_output_action(output_sequence):
    log("FAIL: unexpected output:")
    print_a_sequence(output_sequence)
    log("")

  return bitstring.BitString(output_sequence)

def reset_on_sd_serial_handler(line):
  log(line)
  if 'Self-destruct' in line.decode("utf-8"):
    print_any_serial()
    log("Resetting Target")
    release_reset_and_wait()
    print_any_serial()
    return True
  return False

def logging_serial_handler(line):
  log(line)
  return False

default_serial_handler = reset_on_sd_serial_handler

def send_and_receive(send_sequence):
   def unexpected_output_action(test_bytes):
      return False
   return clock_in_clock_out(send_sequence, blanksss, single_clk_pulse, unexpected_output_action, logging_serial_handler)

passwords = [
b'princess',
b'fob',
b'qwerty',
b'secr3t',
b'admin',
b'backdoor',
b'user',
b'password',
b'letmein',
b'passwd',
b'123456',
b'administrator',
b'car',
b'zxcvbn',
b'monkey',
b'hottie',
b'love',
b'userpass',
b'wachtwoord',
b'geheim',
b'secret',
b'manufacturer',
b'tire',
b'brake',
b'gas',
b'riscurino',
b'delft',
b'sanfransisco',
b'shanghai',
b'gears',
b'login',
b'welcome',
b'solo',
b'dragon',
b'zaq1zaq1',
b'iloveyou',
b'monkey',
b'football',
b'starwars',
b'startrek',
b'cheese',
b'pass',
b'riscure',
b'aes',
b'des'
]

def try_responses(password_prepare, message_responder, frame_responder,  name=None):
  for password in passwords:
    if name is None:
      name = str(password_prepare)+str(message_responder)+str(frame_responder)

    log("\n%s (%s):" % (password, name))

    def unexpected_output_action(test_bytes):
      return False
    challenge_instigate = instigat

    challenge_sequence = clock_in_clock_out(challenge_instigate, blanksss, single_clk_pulse, unexpected_output_action, default_serial_handler)

    log("challenge: %s" % challenge_sequence.hex)

    password_sequence = password_prepare(bitstring.BitString(password))
    message_response_sequence = message_responder(password_sequence, challenge_sequence[:128])
    frame_response_sequence = frame_responder(message_response_sequence, challenge_sequence)
    log("response:  %s" % frame_response_sequence.hex)

    def unexpected_output_action(test_bytes):
      if not bitstring.BitString(test_bytes) == blanksss:
        return True
      return False

    def anything_but_testmode_serial_handler(line):
      log(line)
      if 'Test mode activated' in line.decode("utf-8"):
        return False
      return True

    result_sequence = clock_in_clock_out(frame_response_sequence, blanksss, single_clk_pulse, unexpected_output_action, anything_but_testmode_serial_handler)

    if result_sequence != blanksss:
      log("=====================================================================================")
      log("FLAG (???)")
      log("result   : %s" % result_sequence.hex)
      log("=====================================================================================")
      with open('flags.txt', 'a') as the_file:
        the_file.write("\n%s (%s):\n" % (password, name))
        the_file.write("challenge: %s\n" % challenge_sequence.hex)
        the_file.write("response : %s\n" % frame_response_sequence.hex)
        the_file.write("result   : %s\n" % result_sequence.hex)
  return

def test_roundtrip(expected_sequence):
  actual_sequence = send_and_receive(expected_sequence)
  if actual_sequence != expected_sequence:
    log("sent    : %s" % expected_sequence.hex)
    log("received: %s" % actual_sequence.hex)
    return False
  return True

def explore_after_instigate():
  enable_shift()
  test_shift_depth()
  disable_shift()

  test_roundtrip(instigat)
  enable_shift()
  test_shift_depth()
  disable_shift()

#  changing_bits = blanksss.copy()
#  for bit in range(0,512):
#    log('')
#    test_roundtrip(instigat)
#
#    test_sequence = blanksss.copy()
#    test_sequence.set(1, [bit])
#    if not test_roundtrip(test_sequence):
#      changing_bits |= test_sequence
#
#  log("changing bits: %s" % changing_bits.hex)
  return

def walk_all_response_offset():
  for offset in range(0,512):
    log('')
    test_roundtrip(instigat)
    response_sequence = blanksss.copy()
    response_sequence.overwrite(bitstring.BitString(bin='1'*128), offset)
    test_roundtrip(response_sequence)
  return

def trigger_challenge_algorithm():
  test_roundtrip(instigat)
  response_sequence = onesssss.copy()
  def unexpected_output_action():
    return
  test_roundtrip(response_sequence)
  return

def sustain_the_challenge():
   def unexpected_output_action(test_bytes):
      return False
   clock_in_clock_out(instigat, instigat, single_clk_pulse, unexpected_output_action, logging_serial_handler)
   clock_in_clock_out(instigat, instigat, single_clk_pulse, unexpected_output_action, logging_serial_handler)
   return

###########################################################################

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
      response_sequence.overwrite(response_sequence[:128].reverse(), 0)
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
   response_sequence.overwrite(response_sequence[:128].reverse(), 0)
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
    response_sequence = bitswap(response_sequence)
    response_sequence.overwrite(response_sequence[:128].reverse(), 0)
    return response_sequence
  return rev_bitswapped_responder

##################################################################################
# Frame responders

def get_setbit_responder(bits2set):
   def setbit_responder(message_response_sequence, frame_challenge_sequence):
      return pad_out(message_response_sequence, 512) | bits2set
   return setbit_responder

def get_offset_responder(offset):
  def offset_responder(message_response_sequence, frame_challenge_sequence):
    frame_response_sequence = blanksss.copy()
    frame_response_sequence.overwrite(message_response_sequence, offset)
    return frame_response_sequence
  return offset_responder

def get_offset_ored_responder(offset):
  def offset_ored_responder(message_response_sequence, frame_challenge_sequence):
    frame_response_sequence = frame_challenge_sequence.copy()
    frame_response_sequence.overwrite(message_response_sequence, offset)
    return frame_response_sequence
  return offset_ored_responder

##################################################################################

def try_all_challenges():
  for frame_responder in [get_offset_responder(384-24), get_offset_responder(384)]: # [get_setbit_responder(instigat), get_setbit_responder(sd_alone), get_setbit_responder(sd_count), get_setbit_responder(sd_alone | sd_count), get_setbit_responder(instigat | sd_alone | sd_count), get_setbit_responder(blanksss),get_offset_responder(128), get_offset_responder(256), get_offset_responder(384)]:
    for variant_responder in [get_trivial_responder, get_rev_responder, get_swp_responder, get_swprev_responder]:
        for password_prepare in [pad_password, md5_password]:
           for operation in [encrypt, decrypt]:
              for cipher in [aes_ecb, aes_ctr, aes_cbc]:
                 try_responses(password_prepare, variant_responder(get_cipher_message_responder(operation, cipher)), frame_responder, name=str(password_prepare)+str(variant_responder)+str(operation)+str(cipher)+str(frame_responder))
        for password_prepare in [trivial, pad_password]:
           for message_responder in [hmacmd5, md5concat]:
                 try_responses(password_prepare, variant_responder(message_responder), frame_responder, name=str(password_prepare)+str(variant_responder)+str(message_responder)+str(frame_responder))
        for password_prepare in [pad_password]:
           try_responses(password_prepare, variant_responder(xor), frame_responder,name=str(password_prepare)+str(variant_responder)+str(xor)+str(frame_responder) )
  return

def try_suggested_challenges():
  for frame_responder in [get_offset_ored_responder(384-24), get_offset_ored_responder(128), get_offset_ored_responder(0)]:
    for variant_responder in [get_bitswapped_responder, get_rev_bitswapped_responder, get_rev_responder]:
        for password_prepare in [pad_password, md5_password]:
           for operation in [encrypt, decrypt]:
              for cipher in [aes_ecb]:
                 try_responses(password_prepare, variant_responder(get_cipher_message_responder(operation, cipher)), frame_responder, name=str(password_prepare)+str(variant_responder)+str(operation)+str(cipher)+str(frame_responder))
        for password_prepare in [trivial, pad_password]:
           for message_responder in [hmacmd5, md5concat]:
                 try_responses(password_prepare, variant_responder(message_responder), frame_responder, name=str(password_prepare)+str(variant_responder)+str(message_responder)+str(frame_responder))
  return

def try_jb_challenges():
  for i in range(0,512-128-24):
    frame_responder = get_offset_responder(i)
    for variant_responder in [get_rev_responder, get_bitswapped_responder, get_rev_bitswapped_responder]:
        for password_prepare in [pad_password]:
           for operation in [encrypt, decrypt]:
              for cipher in [aes_ecb]:
                 try_responses(password_prepare, variant_responder(get_cipher_message_responder(operation, cipher)), frame_responder, name=str(password_prepare)+str(variant_responder)+str(operation)+str(cipher)+str(frame_responder))
  return

def try_aes_challenges():
  for frame_responder in [get_offset_ored_responder(356), get_offset_ored_responder(356-128), get_offset_responder(512-128-25-128)]:
    for variant_responder in [get_rev_responder, get_bitswapped_responder, get_rev_bitswapped_responder]:
        for password_prepare in [ssl_password, pad_password]:
           for operation in [encrypt, decrypt]:
              for cipher in [aes_ecb]:
                 try_responses(password_prepare, variant_responder(get_cipher_message_responder(operation, cipher)), frame_responder, name=str(password_prepare)+str(variant_responder)+str(operation)+str(cipher)+str(frame_responder))
  return



# TODO send the nonce back unchanged and set all the read only-bits
# TODO consider what the bit positions of the read-only bits decode to

#explore_after_instigate()
#walk_all_response_offset()
#trigger_challenge_algorithm()
#sustain_the_challenge()

#try_suggested_challenges()
#try_jb_challenges()
try_aes_challenges()

print_any_serial()
ser.close()
bitbang.close()

