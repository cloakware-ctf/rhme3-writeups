#!/usr/bin/env python3

# deps can be satisfied on Linux with `sudo pip3 install pyftdi`

from pyftdi.gpio import GpioController, GpioException
from time import sleep
import sys
import serial
import bitstring
import hmac
import hashlib

#bitstring.bytealigned = True     # change the default behaviour

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

def shift_in_and_out_sequence(tx):
  shift_size = tx.len

  log("  sending : %s" % tx.hex)
  rx = bitstring.BitString(length=shift_size)
  for i in range(0, shift_size):
    pin_low(CLK)
    #assuming MSB first
    set_pin(MOSI, tx[i])
    sleep(DELAY)

    pin_high(CLK)
    sleep(DELAY)
    rx.set(get_pin(MISO), [i])

  pin_low(CLK)
  log("  received: %s" % rx.hex)
  return rx

def shift_in_and_out_sequence_until(match):
  MAX_DEPTH = 1024
  log("  shifting until: %s" % match.hex)
  rx = bitstring.BitString(length=0)

  i = 0
  while True:
    pin_low(CLK)
    #assuming MSB first
    set_pin(MOSI, match[i % match.len])
    sleep(DELAY)

    pin_high(CLK)
    sleep(DELAY)
    rx.append(bitstring.BitString(bin='%d' % get_pin(MISO)))

    if rx.endswith(match):
      break
    i = i + 1
    if i > MAX_DEPTH:
      break

  pin_low(CLK)

  if rx.len % 4 == 0:
    display = rx.hex
  else:
    display = rx.bin
  log("  received: %s" % display)
  return rx


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
#                                   AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD quadwords
ro_bits  = bitstring.BitString(hex='000000000000000000000000000000000000350500000000286e00000c05000000000000000000000000000020001e3000000000055500000000000000000000')
instigat = bitstring.BitString(hex='00000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000')
sd_alone = bitstring.BitString(hex='00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000000000000000')
sd_count = bitstring.BitString(hex='00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000')
#                                   fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe000000

def test_shift_depth():
  MAX_DEPTH = 1024

  def test_miso_goes_high():
    pin_high(MOSI)
    for i in range(0, MAX_DEPTH):
      pin_high(CLK)
      sleep(DELAY)
      if get_pin(MISO):
        log("MISO high on count %d, clk-rising" % i)
        for j in range(i,MAX_DEPTH):
          single_clk_pulse()
        break

      pin_low(CLK)
      sleep(DELAY)
      if get_pin(MISO):
        log("MISO high on count %s, clk-falling" % i)
        for j in range(i,MAX_DEPTH):
          single_clk_pulse()
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
        for j in range(i,MAX_DEPTH):
          single_clk_pulse()
        break

      pin_low(CLK)
      sleep(DELAY)
      if not get_pin(MISO):
        log("MISO low on count %s, clk-falling" % i)
        for j in range(i,MAX_DEPTH):
          single_clk_pulse()
        break

    if get_pin(MISO):
      log("MISO did not change state to low after %d CLKs" % MAX_DEPTH)

    return

  if get_pin(MISO):
    shift_in_and_out_sequence(bitstring.BitString(bin='1'*MAX_DEPTH))
    test_miso_goes_low()
    test_miso_goes_high()
  else:
    shift_in_and_out_sequence(bitstring.BitString(bin='0'*MAX_DEPTH))
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

def single_frame_send_and_receive(send_sequence):
  enable_shift()

  receive_sequence = shift_in_and_out_sequence(send_sequence)

  disable_shift()
  return receive_sequence

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
    return True, line
  return False, line

def logging_serial_handler(line):
  log(line)
  return False, line

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
        return True, line
      return False, line

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
from cr_methods import *

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

# short frame responders
def get_quadA_responder():
  def quadA_responder(message_response_sequence, frame_challenge_sequence):
    frame_response_sequence = message_response_sequence.copy()
    frame_response_sequence.append(bitstring.BitString(bin='0'*384))
    return frame_response_sequence
  return quadA_responder

def get_quadB_responder():
  def quadB_responder(message_response_sequence, frame_challenge_sequence):
    frame_response_sequence = message_response_sequence.copy()
    frame_response_sequence.append(bitstring.BitString(bin='0'*256))
    frame_response_sequence.prepend(bitstring.BitString(bin='0'*128))
    return frame_response_sequence
  return quadB_responder

def get_quadA_andauth_responder():
  def quadA_responder(message_response_sequence, frame_challenge_sequence):
    frame_response_sequence = bitstring.BitString(hex='000000000000000000000000000000000000000000000000000000000000000000000000000000000000000055555555555555555555555555555555defea7ed') # worked once
    frame_response_sequence.overwrite(message_response_sequence, 0)
    return frame_response_sequence
  return quadA_responder

def get_quadB_andauth_responder():
  def quadA_responder(message_response_sequence, frame_challenge_sequence):
    frame_response_sequence = bitstring.BitString(hex='000000000000000000000000000000000000000000000000000000000000000000000000000000000000000055555555555555555555555555555555defea7ed') # worked once
    frame_response_sequence.overwrite(frame_challenge_sequence[128:], 0)
    frame_response_sequence.overwrite(message_response_sequence,128)
    return frame_response_sequence
  return quadA_responder
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

def get_and_handle_serial(serial_handler):
  line = get_any_serial()
  if not line == '':
    if not serial_handler(line):
      log("fatal serial message. aborting.")
      log("")
      return False, line
  return True, line

def quick_instigate_challenge(serial_handler):
  frameA_rx = single_frame_send_and_receive(instigat[-160:]) #minimum number of bits to instigate is 158, nearest multiple of 4 (for hex encoding printing) is 160
  if not get_and_handle_serial(serial_handler):
    return None

  log("end frame")
  single_clk_pulse()
  if not get_and_handle_serial(serial_handler):
    return None
  return frameA_rx

def try_just128bit_experiment():
  #release_reset_and_wait()
  serial_handler = logging_serial_handler

  frameA_rx = quick_instigate_challenge(serial_handler)
  if frameA_rx is None:
    return None

  frameB1_rx = single_frame_send_and_receive(bitstring.BitString(hex='00'*16))
  if not get_and_handle_serial(serial_handler):
    return None

  frameB2_rx = single_frame_send_and_receive(bitstring.BitString(hex='CC'*16))
  if not get_and_handle_serial(serial_handler):
    return None

  log("end frame")
  single_clk_pulse()
  if not get_and_handle_serial(serial_handler):
    return None

  frameC_rx = quick_instigate_challenge(serial_handler)
  if frameC_rx is None:
    return None

  frameD1_rx = single_frame_send_and_receive(bitstring.BitString(hex='00'*16))
  if not get_and_handle_serial(serial_handler):
    return None

  frameD2_rx = single_frame_send_and_receive(bitstring.BitString(hex='CC'*16))
  if not get_and_handle_serial(serial_handler):
    return None

  log("end frame")
  single_clk_pulse()
  if not get_and_handle_serial(serial_handler):
    return None
  return

def explore_frames_shiftdepth():
  serial_handler = logging_serial_handler

  sentinel = bitstring.BitString(hex='DEFEA7ED55555555555555555555555555555555')

  enable_shift()
  rx = shift_in_and_out_sequence_until(sentinel)
  log("frameA shift depth: %d" % (rx.len - sentinel.len))
  get_and_handle_serial(serial_handler)
  shift_in_and_out_sequence(instigat[-160:]) #quick instigate
  disable_shift()
  single_clk_pulse()
  get_and_handle_serial(serial_handler)

  enable_shift()
  rx = shift_in_and_out_sequence_until(sentinel)
  get_and_handle_serial(serial_handler)
  log("frameB shift depth: %d" % (rx.len - sentinel.len))
  disable_shift()
  single_clk_pulse()
  get_and_handle_serial(serial_handler)

  enable_shift()
  rx = shift_in_and_out_sequence_until(sentinel)
  get_and_handle_serial(serial_handler)
  log("frameC shift depth: %d" % (rx.len - sentinel.len))
  disable_shift()
  single_clk_pulse()
  get_and_handle_serial(serial_handler)

  return

def guess_frameB_auth_bit():
  serial_handler = logging_serial_handler

  enable_shift()
  shift_in_and_out_sequence(instigat[-160:]) #quick instigate
  disable_shift()
  single_clk_pulse()
  get_and_handle_serial(serial_handler)

  trailer=bitstring.BitString(hex='55555555555555555555555555555555DEFEA7ED')
  test_bit = bitstring.BitString(bin='0'*512)
  test_bit.overwrite(trailer, 512-trailer.len)
  enable_shift()
  rx = shift_in_and_out_sequence(test_bit)
  disable_shift()
  single_clk_pulse()
  get_and_handle_serial(serial_handler)

  sleep(1)
  get_and_handle_serial(serial_handler)
  return

def explore_frameB_bits():
  serial_handler = logging_serial_handler

  for bit in range(512-128, 0, -1):
    release_reset_and_wait()
    enable_shift()
    shift_in_and_out_sequence(instigat[-160:]) #quick instigate
    disable_shift()
    single_clk_pulse()
    get_and_handle_serial(serial_handler)

    test_bit = bitstring.BitString(bin='0'*512)
    test_bit.set(1, [bit])
    enable_shift()
    rx = shift_in_and_out_sequence(test_bit)
    disable_shift()
    single_clk_pulse()
    get_and_handle_serial(serial_handler)

  return

def try_frameB_response(password_bytes, password_prepare, message_responder, frame_responder, name=None):
  serial_handler = reset_on_sd_serial_handler
  serial_output = bytearray(b'')

  if name is None:
    name = str(password_bytes)+str(password_prepare)+str(message_responder)

  log("\n%s" % name)

  frameA_rx = quick_instigate_challenge(serial_handler)
  if frameA_rx is None:
    return None

  challenge_sequence = single_frame_send_and_receive(bitstring.BitString(hex='00'*16))
  ok, line = get_and_handle_serial(serial_handler)
  if not ok:
    return None
  serial_output.extend(line)
  log("challenge:  %s" % challenge_sequence.hex)

  password_sequence = password_prepare(bitstring.BitString(password_bytes))
  log("prepared :  %s" % password_sequence.hex)

  message_response_sequence = message_responder(password_sequence, challenge_sequence)
  frame_response_sequence = frame_responder(message_response_sequence, challenge_sequence)
  log("response :  %s" % frame_response_sequence.hex)

  single_frame_send_and_receive(frame_response_sequence)
  ok, line = get_and_handle_serial(serial_handler)
  if not ok:
    return None
  serial_output.extend(line)

  log("end frame")
  single_clk_pulse()
  ok, line = get_and_handle_serial(serial_handler)
  if not ok:
    return None
  serial_output.extend(line)

  result_sequence = single_frame_send_and_receive(bitstring.BitString(bin='0'*512))
  log("end frame")
  single_clk_pulse()
  ok, line = get_and_handle_serial(serial_handler)
  if not ok:
    return None
  serial_output.extend(line)

  if not 'Authentication failed' in serial_output.decode('utf-8'):
    log("=====================================================================================")
    log("FLAG (???)")
    log("result   : %s" % result_sequence.hex)
    log("=====================================================================================")
    with open('flags.txt', 'a') as the_file:
      the_file.write("\n%s\n" % name)
      the_file.write("challenge: %s\n" % challenge_sequence.hex)
      the_file.write("response : %s\n" % message_response_sequence.hex)
      the_file.write("result   : %s\n" % result_sequence.hex)
      the_file.write("serial   : %s\n" % serial_output)
  return

def try_all_aes_frameB_challenges():
  for argsorder_responder in [get_trivial_responder, get_swp_responder]:
    for password_prepare in [pad_password, ssl_password, md5_password]: # pad_password
      for frame_responder in [get_quadA_andauth_responder(), get_quadB_andauth_responder()]:
        for variant_responder in [get_rev_responder, get_bitswapped_responder, get_rev_bitswapped_responder, get_trivial_responder]:
          for operation in [encrypt, decrypt]:
            for cipher in [aes_ecb]:
              for password in passwords:
                try_frameB_response(password, password_prepare, variant_responder(argsorder_responder(get_cipher_message_responder(operation, cipher))), frame_responder, name=str(password)+str(password_prepare)+str(variant_responder)+str(argsorder_responder)+str(operation)+str(cipher)+str(frame_responder))
  return

def try_aes_frameB_challenges():
  for frame_responder in [get_quadA_andauth_responder()]:
    for variant_responder in [get_rev_responder, get_bitswapped_responder, get_rev_bitswapped_responder, get_trivial_responder]:
        for password_prepare in [pad_password, ssl_password2, ssl_password, md5_password]:
           for operation in [encrypt, decrypt]:
              for cipher in [aes_ecb]:
                for password in passwords:
                  try_frameB_response(password, password_prepare, variant_responder(get_cipher_message_responder(operation, cipher)), frame_responder, name=str(password)+str(password_prepare)+str(variant_responder)+str(operation)+str(cipher)+str(frame_responder))
  return

def continue_aes_frameB_challenges():
  for frame_responder in [get_quadA_andauth_responder()]:
    for variant_responder in [get_trivial_responder]:
        for password_prepare in [pad_password, ssl_password2, ssl_password, md5_password]:
           for operation in [encrypt, decrypt]:
              for cipher in [aes_ecb]:
                for password in passwords:
                  try_frameB_response(password, password_prepare, variant_responder(get_cipher_message_responder(operation, cipher)), frame_responder, name=str(password)+str(password_prepare)+str(variant_responder)+str(operation)+str(cipher)+str(frame_responder))
  for frame_responder in [get_quadB_andauth_responder()]:
    for variant_responder in [get_rev_responder, get_bitswapped_responder, get_rev_bitswapped_responder, get_trivial_responder]:
        for password_prepare in [pad_password, ssl_password2, ssl_password, md5_password]:
           for operation in [encrypt, decrypt]:
              for cipher in [aes_ecb]:
                for password in passwords:
                  try_frameB_response(password, password_prepare, variant_responder(get_cipher_message_responder(operation, cipher)), frame_responder, name=str(password)+str(password_prepare)+str(variant_responder)+str(operation)+str(cipher)+str(frame_responder))
  return

def continue_swapped_aes_frameB_challenges():
  for frame_responder in [get_quadB_andauth_responder(), get_quadA_andauth_responder()]:
    for variant_responder in [get_rev_responder, get_bitswapped_responder, get_rev_bitswapped_responder, get_trivial_responder]:
      for argsorder_responder in [get_swp_responder]: #get_trivial_responder
        for password_prepare in [pad_password, ssl_password2, ssl_password, md5_password]:
          for operation in [encrypt, decrypt]:
            for cipher in [aes_ecb]:
              for password in passwords:
                try_frameB_response(password, password_prepare, variant_responder(argsorder_responder(get_cipher_message_responder(operation, cipher))), frame_responder, name=str(password)+str(password_prepare)+str(variant_responder)+str(argsorder_responder)+str(operation)+str(cipher)+str(frame_responder))
  return

# TODO send the nonce back unchanged and set all the read only-bits
# TODO consider what the bit positions of the read-only bits decode to

#explore_after_instigate()
#walk_all_response_offset()
#trigger_challenge_algorithm()
#sustain_the_challenge()

#try_suggested_challenges()
#try_jb_challenges()
#try_aes_challenges()

#try_just128bit_experiment()
#try_aes_frameB_challenges()
#continue_aes_frameB_challenges()
#continue_swapped_aes_frameB_challenges()
try_all_aes_frameB_challenges()

#explore_frames_shiftdepth()
#explore_frameB_bits()
#guess_frameB_auth_bit()

print_any_serial()
ser.close()
bitbang.close()

