from frames_protocol import *
import sys
import socket

target_count = -1

def try_frameB_response(frameB_sequence):
  global target_count

  target_count = (target_count + 1) % 512

  serial_handler = reset_on_sd_serial_handler
  serial_output = bytearray(b'')

  log("\n")
  enable_shift()

  frameA_rx = shift_in_and_out_sequence(instigat[-160:]) #minimum number of bits to instigate is 158, nearest multiple of 4 (for hex encoding printing) is 160

  disable_shift()

  if not get_and_handle_serial(serial_handler):
    return None

  log("end frame")
  pin_high(TRIG_OUT)
  single_clk_pulse()
  pin_low(TRIG_OUT)

  if not get_and_handle_serial(serial_handler):
    return None

  if frameA_rx is None:
    return None

  enable_shift()

  challenge_sequence = shift_in_and_out_sequence(bitstring.BitString(hex='00'*16))

  disable_shift()

  ok, line = get_and_handle_serial(serial_handler)
  if not ok:
    return None
  serial_output.extend(line)
  log("challenge:  %s" % challenge_sequence.hex)

  frameB_sequence = frameB_sequence.copy()
  frameB_sequence |= authicat
  frameB_sequence &= ~(sd_count | sd_alone)

  enable_shift()

  tx = frameB_sequence
  shift_size = tx.len

  log("  sending : %s" % tx.hex)
  rx = bitstring.BitString(length=shift_size)
  for i in range(0, shift_size):
    pin_low(CLK)
    #assuming MSB first
    set_pin(MOSI, tx[i])
    sleep(DELAY)

#    if i == target_count:
#      log("triggering count %d" % i)
#      pin_high(TRIG_OUT)
    pin_high(CLK)
    sleep(DELAY)
#    if i == target_count:
#      pin_low(TRIG_OUT)
    rx.set(get_pin(MISO), [i])

  pin_low(CLK)
  log("  received: %s" % rx.hex)

  disable_shift()

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
    while True:
      line = self.rfile.readline().decode('utf-8')
      to_send = bitstring.BitString(hex=line)
      to_send = pad_out(to_send, 512)

      challenge = try_frameB_response(to_send)

      out = "%s\n" % challenge.hex
      self.wfile.write(out.encode('utf-8'))


if __name__ == "__main__":
  pin_low(TRIG_OUT)
  server = socketserver.TCPServer(('', 32888), FrameBHandler)
  server.serve_forever()

