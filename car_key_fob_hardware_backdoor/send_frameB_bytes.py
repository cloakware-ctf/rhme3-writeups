from frames_protocol import *
import sys
import socket

def try_frameB_response(frameB_sequence):
  serial_handler = reset_on_sd_serial_handler
  serial_output = bytearray(b'')

  log("\n")

  frameA_rx = quick_instigate_challenge(serial_handler)
  if frameA_rx is None:
    return None

  challenge_sequence = single_frame_send_and_receive(bitstring.BitString(hex='00'*16))
  ok, line = get_and_handle_serial(serial_handler)
  if not ok:
    return None
  serial_output.extend(line)
  log("challenge:  %s" % challenge_sequence.hex)

  frameB_sequence = frameB_sequence.copy()
  frameB_sequence |= authicat

  pin_high(TRIG_OUT) # interesting stuff happens in frameB here

  single_frame_send_and_receive(frameB_sequence)

  pin_low(TRIG_OUT) # interesting area over now

  ok, line = get_and_handle_serial(serial_handler)
  if not ok:
    return None
  serial_output.extend(line)

  log("end frame")
  single_clk_pulse()

  ok, line = get_and_handle_serial(serial_handler)
  if not ok:
    return None
  serial_output.extend(line)

  result_sequence = single_frame_send_and_receive(bitstring.BitString(bin='0'*512))

  log("end frame")
  single_clk_pulse()

  ok, line = get_and_handle_serial(serial_handler)
  if not ok:
    return None
  serial_output.extend(line)

  return challenge_sequence

import socketserver

class FrameBHandler(socketserver.StreamRequestHandler):
  def handle(self):
    line = self.rfile.readline().decode('utf-8')
    to_send = bitstring.BitString(hex=line)
    to_send = pad_out(to_send, 512)

    challenge = try_frameB_response(to_send)

    out = "%s\n" % challenge.hex
    self.wfile.write(out.encode('utf-8'))

if __name__ == "__main__":
  server = socketserver.TCPServer(('', 32888), FrameBHandler)
  server.serve_forever()

