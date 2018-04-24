from frames_protocol import *
import sys
import socket

def get_challenge():
  serial_handler = reset_on_sd_serial_handler
  serial_output = bytearray(b'')

  frameA_rx = quick_instigate_challenge(serial_handler)
  if frameA_rx is None:
    return None

  challenge_sequence = single_frame_send_and_receive(bitstring.BitString(hex='00'*16))
  ok, line = get_and_handle_serial(serial_handler)
  if not ok:
    return None
  serial_output.extend(line)
  log("challenge:  %s" % challenge_sequence.hex)

  ok, line = get_and_handle_serial(serial_handler)
  if not ok:
    return None
  serial_output.extend(line)

  return challenge_sequence

for i in range(0,100):
  sys.stderr.write("%s\n" % get_challenge().hex)

