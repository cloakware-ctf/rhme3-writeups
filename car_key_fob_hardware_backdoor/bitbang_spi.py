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

CLK = 0
MOSI = 1
MISO = 2
CS = 3

pin_high(CLK)
pin_output(CLK)

pin_high(CS)
pin_output(CS)

pin_high(MOSI)
pin_output(MOSI)

pin_low(CS)
for i in range(0, 128):
    pin_high(CLK)
    sleep(0.00055)

    pin_low(CLK)
    sleep(0.00054)

pin_high(CLK)
pin_high(CS)

#bitbang.Close()
bitbang.close()

