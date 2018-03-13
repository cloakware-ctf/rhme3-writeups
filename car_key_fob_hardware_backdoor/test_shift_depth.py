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

def get_pin(line):
    state = bitbang.read_port()
    return bool(state & (1 << line))
# SPI Name | MPSSE # | MPSSE Color | RHME3 Pin | Function Guess
MISO       = 2       # GREEN       | A5        | DO
MOSI       = 1       # YELLOW      | A4        | DI
CS         = 3       # BROWN       | A3        | LATCH
CLK        = 0       # ORANGE      | A2        | CLK
RESET      = 4       # GREY        | RESET     | RESET

pin_high(RESET)
pin_output(RESET)
pin_low(RESET)

pin_low(CLK)
pin_output(CLK)

pin_low(CS)
pin_output(CS)

pin_low(MOSI)
pin_output(MOSI)

pin_input(MISO)

pin_high(RESET)
print(ser.readline())
ser.close()
ser = serial.Serial('/dev/ttyUSB0', 115200, timeout=0)

#set MOSI high and clock until we see the high propagate
if get_pin(MISO):
    print("MISO already high\n")
    sys.exit(1)

pin_high(CS)
sleep(DELAY)

pin_high(MOSI)
sleep(DELAY)

MAX_DEPTH = 4096

for i in range(0, MAX_DEPTH):
    pin_high(CLK)
    sleep(DELAY)
    if get_pin(MISO):
        print("MISO high on count %d, clk-rising\n" % i)
        break

    pin_low(CLK)
    sleep(0.00054)
    if get_pin(MISO):
        print("MISO high on count %s, clk-falling\n" % i)
        break

pin_low(MOSI)
for i in range(0, MAX_DEPTH):
    pin_high(CLK)
    sleep(DELAY)
    if not get_pin(MISO):
        print("MISO low on count %d, clk-rising\n" % i)
        break

    pin_low(CLK)
    sleep(0.00054)
    if not get_pin(MISO):
        print("MISO low on count %s, clk-falling\n" % i)
        break

bitbang.close()

