#!/usr/bin/env python3

# deps can be satisfied on Linux with `sudo pip3 install pyftdi`

from pyftdi.gpio import GpioController, GpioException
from time import sleep
import sys

bitbang = GpioController()
bitbang.open_from_url('ftdi:///1')

DELAY = 0.00055

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


def shift_in_byte():
    building_byte = 0
    for i in range(0, 8):
        pin_high(CLK)
        sleep(DELAY)

        #assuming MSB first for now
        building_byte = building_byte | (get_pin(MISO) << (7 - i))

        pin_low(CLK)
        sleep(DELAY)

    return building_byte

def shift_in_and_out_byte(tx):
    building_byte = 0
    for i in range(0, 8):
        pin_high(CLK)
        sleep(DELAY)

        #assuming MSB first for now
        building_byte = building_byte | (get_pin(MISO) << (7 - i))
        set_pin(MOSI, bool(tx & (1 << (7 - i))))

        pin_low(CLK)
        sleep(DELAY)

    return building_byte

pin_high(CLK)
pin_output(CLK)

pin_high(CS)
pin_output(CS)

pin_high(MOSI)
pin_output(MOSI)

pin_input(MISO)

# results in shifting-out only 0xffs
# pin_high(CLK)
# pin_low(CS)
# sleep(2 * DELAY)
# 
# pin_low(CLK)
# sleep(2 * DELAY)
# 
# pin_high(CLK)
# pin_high(CS)

# doing it this way results in only 00's
# pin_high(CLK)
# pin_low(CS)
# sleep(2 * DELAY)
# # leave it low for the 512 bit shift that follows...
# ... then after all the clocks below
# pin_high(CS)

pin_high(CLK)
pin_low(CS)
sleep(2 * DELAY)

sentinel = bytearray.fromhex('cafeabad1deadeadbeefdefea7edd00dcafeabad1deadeadbeefdefea7edd00dcafeabad1deadeadbeefdefea7edd00dcafeabad1deadeadbeefdefea7edd00d')

for i in range(0, int(512 / 8)):
    rx = shift_in_and_out_byte(sentinel[i])
    sys.stdout.write("%02x " % rx)
    sys.stdout.flush()

sys.stdout.write('\n')

pin_high(CS)

bitbang.close()

