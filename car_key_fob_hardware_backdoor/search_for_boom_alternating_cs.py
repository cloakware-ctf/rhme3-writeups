#!/usr/bin/env python3

# deps can be satisfied on Linux with `sudo pip3 install pyftdi`

from pyftdi.gpio import GpioController, GpioException
from time import sleep
import sys
import serial

bitbang = GpioController()
bitbang.open_from_url('ftdi:///1')

ser = serial.Serial('/dev/ttyUSB0', 115200, timeout=None)

DELAY = 0.000005 #strict worst-case delay is 0.54ms -- we can relax that due to lots of delays in the many layers of software between us.
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
    pin_high(RESET)
    print(ser.readline())
    #ser.close()
    #ser = serial.Serial('/dev/ttyUSB0', 115200, timeout=0)
    return

release_reset_and_wait()

def print_any_serial():
    global ser
    count = ser.in_waiting
    if count > 0:
        print(ser.readline())
        sys.stdout.flush()
    return

blanksss = bytearray.fromhex('00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000')
sentinel = bytearray.fromhex('cafeabad1deadeadbeefdefea7edd00dcafeabad1deadeadbeefdefea7edd00dcafeabad1deadeadbeefdefea7edd00dcafeabad1deadeadbeefdefea7edd00d')

def test_one_roundtrip(test_sequence, inter_frame_action):
    pin_high(CS)
    sleep(DELAY)

    shifted_out = bytearray()
    for i in range(0, int(512 / 8)):
        rx = shift_in_and_out_byte(test_sequence[i])
        shifted_out.append(rx)
        sys.stdout.write("%02x " % rx)
        sys.stdout.flush()
        print_any_serial()

    pin_low(CS)
    sleep(DELAY)

    if not shifted_out == blanksss:
        sys.stdout.write("FAIL: not expected blank value")
    sys.stdout.write('\n')

    inter_frame_action()

    shifted_out = bytearray()
    for i in range(0, int(512 / 8)):
        rx = shift_in_and_out_byte(test_sequence[i])
        shifted_out.append(rx)
        sys.stdout.write("%02x " % rx)
        sys.stdout.flush()
        print_any_serial()

    pin_low(CS)
    sleep(DELAY)

    if not shifted_out == test_sequence:
        sys.stdout.write("FAIL: not expected test sequence")
    sys.stdout.write('\n')
    return

def single_clk_pulse():
   pin_high(CLK)
   sleep(DELAY)
   pin_low(CLK)
   sleep(DELAY)
   return

for rep in range(0,10):
   test_one_roundtrip(sentinel, single_clk_pulse)

print_any_serial()
ser.close()
bitbang.close()

