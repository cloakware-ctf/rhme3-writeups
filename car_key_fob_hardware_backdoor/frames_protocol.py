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

pin_low(TRIG_OUT)
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
ro_bits  = bitstring.BitString(hex='000000000000000000000000000000000000350500000000286e00000c05000000000000000000000000000000001e3000000000055500000000000000000000')
specials = bitstring.BitString(hex='000000000000000000000000000000000000350500000000287e00000c05000000000000000000000000000030001e3000000000055500002008000000000000')
b_stuck  = bitstring.BitString(hex='000000000000000000000000000000000000350500000000286e00000c05000000000000000000000000000000001e3000000000055500000000000000000000') # stuck bits tested in frame B
led      = bitstring.BitString(hex='00000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000')
instigat = bitstring.BitString(hex='00000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000')
authicat = bitstring.BitString(hex='00000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000')
sd_alone = bitstring.BitString(hex='00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000000000000000')
sd_count = bitstring.BitString(hex='00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000')
#                                   fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe000000

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
def get_quadA_andauth_responder():
  def quadA_responder(message_response_sequence, frame_challenge_sequence):
    frame_response_sequence = authicat.copy()
    frame_response_sequence.overwrite(message_response_sequence, 0)
    return frame_response_sequence
  return quadA_responder

def get_quadB_andauth_responder():
  def quadB_responder(message_response_sequence, frame_challenge_sequence):
    frame_response_sequence = authicat.copy()
    frame_response_sequence.overwrite(frame_challenge_sequence[:128], 0)
    frame_response_sequence.overwrite(message_response_sequence, 128)
    return frame_response_sequence
  return quadB_responder

def get_quadD_andauth_responder():
  def quadD_responder(message_response_sequence, frame_challenge_sequence):
    frame_response_sequence = authicat.copy()
    frame_response_sequence.overwrite(message_response_sequence, 128*3)
    frame_response_sequence = frame_response_sequence[-160:]
    return frame_response_sequence
  return quadD_responder

def get_lsb_offet_and_auth_responder(offset):
  def lsb_offset_responder(message_response_sequence, frame_challenge_sequence):
    frame_response_sequence = authicat.copy()
    frame_response_sequence.overwrite(message_response_sequence, offset-127)
    return frame_response_sequence
  return lsb_offset_responder

def get_msb_offet_and_auth_responder(offset):
  def msb_offset_responder(message_response_sequence, frame_challenge_sequence):
    frame_response_sequence = authicat.copy()
    frame_response_sequence.overwrite(message_response_sequence, offset)
    frame_response_sequence = frame_response_sequence[int(offset/4)*4:]
    return frame_response_sequence
  return msb_offset_responder

def get_msb_offset_and_auth_avoidstuckbits_by_bit(offset):
  def msb_offset_and_auth_avoidstuckbits_by_bit_responder(message_response_sequence, frame_challenge_sequence):
    frame_response_sequence = authicat.copy()

    target_index = offset
    for source_index in range(0, 128):
      while b_stuck[target_index]:
        target_index += 1
      frame_response_sequence[target_index] = message_response_sequence[source_index]
      target_index += 1

    frame_response_sequence = frame_response_sequence[int(offset/4)*4:]
    return frame_response_sequence
  return msb_offset_and_auth_avoidstuckbits_by_bit_responder

##################################################################################

def quick_instigate_challenge(serial_handler):
  frameA_rx = single_frame_send_and_receive(instigat[-160:]) #minimum number of bits to instigate is 158, nearest multiple of 4 (for hex encoding printing) is 160
  if not get_and_handle_serial(serial_handler):
    return None

  log("end frame")
  single_clk_pulse()
  if not get_and_handle_serial(serial_handler):
    return None
  return frameA_rx

def get_and_handle_serial(serial_handler):
  line = get_any_serial()
  if not line == '':
    if not serial_handler(line):
      log("fatal serial message. aborting.")
      log("")
      return False, line
  return True, line


