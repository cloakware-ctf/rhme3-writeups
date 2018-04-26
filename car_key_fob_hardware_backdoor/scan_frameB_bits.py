#!/usr/bin/env python3

from frames_protocol import *
import sys
import socket

def scan_frameB_bits():
  ser.write(b'starting scan')
  for bitnum in range(128, 256):
    log("%d" % bitnum)
    send_frameB_bit(bitnum)

def send_frameB_bit(bitnum):
  serial_handler = reset_on_sd_serial_handler
  serial_output = bytearray(b'')

  log("\n")
  enable_shift()

  frameA_rx = shift_in_and_out_sequence(instigat[-160:]) #minimum number of bits to instigate is 158, nearest multiple of 4 (for hex encoding printing) is 160

  disable_shift()

  if not get_and_handle_serial(serial_handler):
    return None

  log("end frame")
  single_clk_pulse()

  if not get_and_handle_serial(serial_handler):
    return None

  if frameA_rx is None:
    return None

  enable_shift()

  challenge_sequence = shift_in_and_out_sequence(bitstring.BitString(hex='00'*16))

  ok, line = get_and_handle_serial(serial_handler)
  if not ok:
    return None
  serial_output.extend(line)
  log("challenge:  %s" % challenge_sequence.hex)

  frameB_sequence = bitstring.BitString(bin='0'*512)
  frameB_sequence[bitnum] = 1

  shift_in_and_out_sequence(frameB_sequence)
  disable_shift()

  ok, line = get_and_handle_serial(serial_handler)
  if not ok:
    return None
  serial_output.extend(line)

  log("end frame")
  ser.write(bytes([bitnum]))
  single_clk_pulse()

  ok, line = get_and_handle_serial(serial_handler)
  if not ok:
    return None
  serial_output.extend(line)

  #result_sequence = single_frame_send_and_receive(bitstring.BitString(bin='0'*512))

  log("end frame")
  single_clk_pulse()

  ok, line = get_and_handle_serial(serial_handler)
  if not ok:
    return None
  serial_output.extend(line)

  return challenge_sequence


scan_frameB_bits()
