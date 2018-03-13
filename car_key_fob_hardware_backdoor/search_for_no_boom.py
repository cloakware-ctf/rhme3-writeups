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

def print_a_sequence(sequence):
   for i in sequence:
      sys.stdout.write("%02x " % i)
   sys.stdout.flush()
   return

def test_one_roundtrip(test_sequence, inter_frame_action, unexpected_output_action, serial_handler):
    pin_high(CS)
    sleep(DELAY)

    print("Shifting-in test-sequence.")
    shifted_out = bytearray()
    for i in range(0, int(512 / 8)):
        rx = shift_in_and_out_byte(test_sequence[i])
        shifted_out.append(rx)
        line = get_any_serial()
        if not line == '':
           if serial_handler(line):
              print("FAIL: serial message on test-sequence:")
              print_a_sequence(test_sequence)
              print("")
              return None

    pin_low(CS)
    sleep(DELAY)

    if not shifted_out == blanksss.tobytes():
        print("FAIL: expected all blanks, got:")
        print_a_sequence(shifted_out)
        print("")

    inter_frame_action()
    line = get_any_serial()
    if not line == '':
        if serial_handler(line):
            print("FAIL: serial message on test-sequence:")
            print_a_sequence(test_sequence)
            print("\n")
            return None

    pin_high(CS)
    sleep(DELAY)

    print("Shifting-out test-sequence. Read:")
    shifted_out = bytearray()
    for i in range(0, int(512 / 8)):
        rx = shift_in_and_out_byte(blanksss.tobytes()[i])
        shifted_out.append(rx)
        sys.stdout.write("%02x " % rx)
        sys.stdout.flush()
    sys.stdout.write('\n')
    line = get_any_serial()
    if not line == '':
        if serial_handler(line):
           print("FAIL: serial message on test-sequence:")
           print_a_sequence(test_sequence)
           print("")
           return None

    pin_low(CS)
    sleep(DELAY)

    if not shifted_out == test_sequence:
        unexpected_output_action(test_sequence, shifted_out)
        print("FAIL: expected test-sequence:")
        print_a_sequence(test_sequence)
        print("")

    return shifted_out

def single_clk_pulse():
   pin_high(CLK)
   sleep(DELAY)
   pin_low(CLK)
   sleep(DELAY)
   return

read_only_bits = blanksss.copy()
def unexpected_output_action(expected_sequence, unexpected_sequence):
   global read_only_bits
   read_only_bits |= bitstring.BitString(expected_sequence)
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

for bit in range(0,512):
   test_sequence = blanksss.copy()
   test_sequence.set(1, [bit])

   test_one_roundtrip(test_sequence.tobytes(), single_clk_pulse, unexpected_output_action, serial_handler)

print("Read-only bits:")
print(read_only_bits.hex)

print_any_serial()
ser.close()
bitbang.close()

