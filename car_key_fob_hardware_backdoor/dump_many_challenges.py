#!/usr/bin/env python3

# deps can be satisfied on Linux with `sudo pip3 install pyftdi`

from pyftdi.gpio import GpioController, GpioException
from time import sleep
import sys
import serial
import bitstring

bitstring.bytealigned = True     # change the default behaviour

bitbang = GpioController()
bitbang.open_from_url('ftdi:///1')

ser = serial.Serial('/dev/ttyUSB0', 115200, timeout=None)

DELAY = 0.0000005 #strict worst-case delay is 0.54ms -- we can relax that due to lots of delays in the many layers of software between us.
                 #on my machine this results in a minimum CLK pulse width of 0.58 ms on my machine
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

def release_reset_and_wait():
    global ser
    pin_low(RESET)
    sleep(2 * DELAY)
    pin_high(RESET)
    while True:
       line = ser.readline()
       print(line)
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
      print(line)
      sys.stdout.flush()
   return

blanksss = bitstring.BitString('0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000')
sentinel = bitstring.BitString('0xcafeabad1deadeadbeefdefea7edd00dcafeabad1deadeadbeefdefea7edd00dcafeabad1deadeadbeefdefea7edd00dcafeabad1deadeadbeefdefea7edd00d')
onesssss = bitstring.BitString('0x11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111')
instigat = bitstring.BitString('0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000')


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
           print("FAIL: serial message on test-sequence:")
           print_a_sequence(input_sequence)
           print("")
           return None

    pin_low(CS)
    sleep(DELAY)

    if not output_sequence == blanksss.tobytes():
        print("FAIL: expected all blanks, got:")
        print_a_sequence(output_sequence)
        print("")

    inter_frame_action()

    line = get_any_serial()
    if not line == '':
        if serial_handler(line):
            print("FAIL: serial message on test-sequence:")
            print_a_sequence(input_sequence)
            print("\n")
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
           print("FAIL: serial message on test-sequence:")
           print_a_sequence(input_sequence)
           print("")
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
      print(line)
      if 'Self-destruct' in line.decode("utf-8"):
         print_any_serial()
         print("Resetting Target")
         release_reset_and_wait()
         print_any_serial()
         return True
      return False

   return bitstring.BitString(clock_in_clock_out(send_sequence.tobytes(), single_clk_pulse, unexpected_output_action, serial_handler))

def read_challenge():
   return send_and_receive(instigat)

def send_response(response_sequence):
   return send_and_receive(response_sequence)

for rep in range(0,100):
   print("\n%d:" % rep)
   challenge_sequence = read_challenge()
   print("challenge: %s" % challenge_sequence.hex)
   response_sequence = blanksss.copy()
   print("response : %s" % response_sequence.hex)
   result_sequence = send_response(response_sequence)
   print("result   : %s" % result_sequence.hex)


print_any_serial()
ser.close()
bitbang.close()

