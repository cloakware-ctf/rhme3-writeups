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

DELAY = 0.00001 #strict worst-case delay is 0.54ms -- we can relax that due to lots of delays in the many layers of software between us.
                 #on my machine this results in a minimum CLK pulse width of 0.69 ms on my machine
HARD_DELAY = 0.00054 # for cases where strict delay adherence is necessary (e.g. when begining shift-out)

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
MISO       = 2       # GREEN       | A5        | DO
MOSI       = 1       # YELLOW      | A4        | DI
CS         = 3       # BROWN       | A3        | LATCH
CLK        = 0       # ORANGE      | A2        | CLK
RESET      = 4       # GREY        | RESET     | RESET

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
instigat = bitstring.BitString(hex='00000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000')
sd_alone = bitstring.BitString(hex='00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000000000000000')
sd_count = bitstring.BitString(hex='00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000')

def print_a_sequence(sequence):
   for i in sequence:
      sys.stdout.write("%02x " % i)
   sys.stdout.flush()
   return

def clock_in_clock_out(input_sequence, inter_frame_action, unexpected_output_action, serial_handler):
    pin_high(CS)
    sleep(HARD_DELAY)

    output_sequence = bytearray()
    for i in range(0, int(512 / 8)):
        rx = shift_in_and_out_byte(input_sequence[i])
        output_sequence.append(rx)

    line = get_any_serial()
    if not line == '':
       if serial_handler(line):
           log("FAIL: serial message on test-sequence:")
           print_a_sequence(input_sequence)
           log("")
           return None

    pin_low(CS)
    sleep(DELAY)

    if not output_sequence == blanksss.tobytes():
        log("FAIL: expected all blanks, got:")
        print_a_sequence(output_sequence)
        log("")

    inter_frame_action()

    line = get_any_serial()
    if not line == '':
        if serial_handler(line):
            log("FAIL: serial message on test-sequence:")
            print_a_sequence(input_sequence)
            log("\n")
            return None

    pin_high(CS)
    sleep(HARD_DELAY)

    output_sequence = bytearray()
    for i in range(0, int(512 / 8)):
        rx = shift_in_and_out_byte(blanksss.tobytes()[i])
        output_sequence.append(rx)

    line = get_any_serial()
    if not line == '':
        if serial_handler(line):
           log("FAIL: serial message on test-sequence:")
           print_a_sequence(input_sequence)
           log("")
           return None

    pin_low(CS)
    sleep(DELAY)

    return output_sequence

def send_and_receive(send_sequence):
   def single_clk_pulse():
      pin_high(CLK)
      sleep(DELAY)
      pin_low(CLK)
      sleep(DELAY)
      return

   def unexpected_output_action(expected_sequence, unexpected_sequence):
      return

   def serial_handler(line):
      log(line)
      if 'Self-destruct' in line.decode("utf-8"):
         print_any_serial()
         log("Resetting Target")
         release_reset_and_wait()
         print_any_serial()
         return True
      return False

   return bitstring.BitString(clock_in_clock_out(send_sequence.tobytes(), single_clk_pulse, unexpected_output_action, serial_handler))

def read_challenge():
   return send_and_receive(instigat)

def send_response(response_sequence):
   return send_and_receive(response_sequence)

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
      challenge_sequence = read_challenge()
      log("challenge: %s" % challenge_sequence.hex)

      password_sequence = password_prepare(bitstring.BitString(password))
      message_response_sequence = message_responder(password_sequence, challenge_sequence[:128])
      frame_response_sequence = frame_responder(message_response_sequence, challenge_sequence)
      log("response:  %s" % frame_response_sequence.hex)

      result_sequence = send_response(frame_response_sequence)
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

##################################################################################

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

# TODO try AES-128 {encrypt,decrypt} of chalenge with key from password {null-padded, md5, pbkdf, pbkdf2} in ECB, CTR and CBC (null IV) modes
# TODO send response AND set one of the 
# TODO send the nonce back unchanged and set all the read only-bits
# TODO consider what the bit positions of the read-only bits decode to

print_any_serial()
ser.close()
bitbang.close()

