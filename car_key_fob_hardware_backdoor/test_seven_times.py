#!/usr/bin/env python3

# deps can be satisfied on Linux with `sudo pip3 install pyftdi`

from pyftdi.gpio import GpioController, GpioException
from time import sleep
import sys
import serial

bitbang = GpioController()
bitbang.open_from_url('ftdi:///1')

ser = serial.Serial('/dev/ttyUSB0', 115200, timeout=2)

DELAY = 0.000001 #strict worst-case delay is 0.55ms -- we can relax that due to lots of delays in the many layers of software between us.
                 #on my machine this results in a minimum CLK pulse width of 200ms

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

def clk_pulse():
    pin_low(CLK)
    sleep(DELAY)
    pin_high(CLK)
    sleep(DELAY)
    return

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

pin_high(RESET)
print(ser.readline())
ser.close()
ser = serial.Serial('/dev/ttyUSB0', 115200, timeout=0)

def print_any_serial():
    global ser
    count = ser.in_waiting
    if count > 0:
        sys.stdout.write(ser.read(count))
        sys.stdout.flush()
    return

blanksss = bytearray.fromhex('ff000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000')
sentinel = bytearray.fromhex('cafeabad1deadeadbeefdefea7edd00dcafeabad1deadeadbeefdefea7edd00dcafeabad1deadeadbeefdefea7edd00dcafeabad1deadeadbeefdefea7edd00d')

for k in range(0,25):
    for i in range(0, int(512 / 8)):
        rx = shift_in_and_out_byte(blanksss[i])
        print_any_serial()
    sleep(DELAY)
    pin_low(CLK)
    pin_high(CS)
    sleep(DELAY)
    clk_pulse()
    clk_pulse()
    pin_low(CLK)
    pin_low(CS)
    sleep(DELAY)

print_any_serial()
ser.close()
bitbang.close()

