#!/usr/bin/env python3

# deps can be satisfied on Linux with `sudo pip3 install pyftdi`

from pyftdi.gpio import GpioController, GpioException
from time import sleep

bitbang = GpioController()
bitbang.open_from_url('ftdi:///1')

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

pin_high(CLK)
pin_output(CLK)

pin_high(CS)
pin_output(CS)

pin_low(MOSI)
pin_output(MOSI)

pin_input(MISO)

#set MOSI high and clock until we see the high propagate
if get_pin(MISO):
    print("MISO already high\n")
pin_high(MOSI)

for i in range(0, 1024):
    pin_high(CLK)
    sleep(0.00055)
    if get_pin(MISO):
        print("MISO high on count %d, clk-rising\n" % i)
        break

    pin_low(CLK)
    sleep(0.00054)
    if get_pin(MISO):
        print("MISO high on count %s, clk-falling\n" % i)
        break

pin_low(MOSI)
for i in range(0, 1024):
    pin_high(CLK)
    sleep(0.00055)
    if not get_pin(MISO):
        print("MISO low on count %d, clk-rising\n" % i)
        break

    pin_low(CLK)
    sleep(0.00054)
    if not get_pin(MISO):
        print("MISO low on count %s, clk-falling\n" % i)
        break

bitbang.close()

