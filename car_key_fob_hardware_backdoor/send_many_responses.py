#!/usr/bin/env python3

from frames_protocol import *

def test_shift_depth():
  MAX_DEPTH = 1024

  def test_miso_goes_high():
    pin_high(MOSI)
    for i in range(0, MAX_DEPTH):
      pin_high(CLK)
      sleep(DELAY)
      if get_pin(MISO):
        log("MISO high on count %d, clk-rising" % i)
        for j in range(i,MAX_DEPTH):
          single_clk_pulse()
        break

      pin_low(CLK)
      sleep(DELAY)
      if get_pin(MISO):
        log("MISO high on count %s, clk-falling" % i)
        for j in range(i,MAX_DEPTH):
          single_clk_pulse()
        break

    if not get_pin(MISO):
      log("MISO did not change state to high after %d CLKs" % MAX_DEPTH)

    return

  def test_miso_goes_low():
    pin_low(MOSI)
    for i in range(0, MAX_DEPTH):
      pin_high(CLK)
      sleep(DELAY)
      if not get_pin(MISO):
        log("MISO low on count %d, clk-rising" % i)
        for j in range(i,MAX_DEPTH):
          single_clk_pulse()
        break

      pin_low(CLK)
      sleep(DELAY)
      if not get_pin(MISO):
        log("MISO low on count %s, clk-falling" % i)
        for j in range(i,MAX_DEPTH):
          single_clk_pulse()
        break

    if get_pin(MISO):
      log("MISO did not change state to low after %d CLKs" % MAX_DEPTH)

    return

  if get_pin(MISO):
    shift_in_and_out_sequence(bitstring.BitString(bin='1'*MAX_DEPTH))
    test_miso_goes_low()
    test_miso_goes_high()
  else:
    shift_in_and_out_sequence(bitstring.BitString(bin='0'*MAX_DEPTH))
    test_miso_goes_high()
    test_miso_goes_low()

  return

from password_candidates import *

def try_responses(password_prepare, message_responder, frame_responder,  name=None):
  for password in passwords:
    if name is None:
      name = str(password_prepare)+str(message_responder)+str(frame_responder)

    log("\n%s (%s):" % (password, name))

    def unexpected_output_action(test_bytes):
      return False
    challenge_instigate = instigat

    challenge_sequence = clock_in_clock_out(challenge_instigate, blanksss, single_clk_pulse, unexpected_output_action, default_serial_handler)

    log("challenge: %s" % challenge_sequence.hex)

    password_sequence = password_prepare(bitstring.BitString(password))
    message_response_sequence = message_responder(password_sequence, challenge_sequence[:128])
    frame_response_sequence = frame_responder(message_response_sequence, challenge_sequence)
    log("response:  %s" % frame_response_sequence.hex)

    def unexpected_output_action(test_bytes):
      if not bitstring.BitString(test_bytes) == blanksss:
        return True
      return False

    def anything_but_testmode_serial_handler(line):
      log(line)
      if 'Test mode activated' in line.decode("utf-8"):
        return True, line
      return False, line

    result_sequence = clock_in_clock_out(frame_response_sequence, blanksss, single_clk_pulse, unexpected_output_action, anything_but_testmode_serial_handler)

    if result_sequence != blanksss:
      log("=====================================================================================")
      log("FLAG (???)")
      log("result   : %s" % result_sequence.hex)
      log("=====================================================================================")
      with open('flags.txt', 'a') as the_file:
        the_file.write("\n%s (%s):\n" % (password, name))
        the_file.write("challenge: %s\n" % challenge_sequence.hex)
        the_file.write("response : %s\n" % frame_response_sequence.hex)
        the_file.write("result   : %s\n" % result_sequence.hex)
  return

def test_roundtrip(expected_sequence):
  actual_sequence = send_and_receive(expected_sequence)
  if actual_sequence != expected_sequence:
    log("sent    : %s" % expected_sequence.hex)
    log("received: %s" % actual_sequence.hex)
    return False
  return True

def explore_after_instigate():
  enable_shift()
  test_shift_depth()
  disable_shift()

  test_roundtrip(instigat)
  enable_shift()
  test_shift_depth()
  disable_shift()

#  changing_bits = blanksss.copy()
#  for bit in range(0,512):
#    log('')
#    test_roundtrip(instigat)
#
#    test_sequence = blanksss.copy()
#    test_sequence.set(1, [bit])
#    if not test_roundtrip(test_sequence):
#      changing_bits |= test_sequence
#
#  log("changing bits: %s" % changing_bits.hex)
  return

def walk_all_response_offset():
  for offset in range(0,512):
    log('')
    test_roundtrip(instigat)
    response_sequence = blanksss.copy()
    response_sequence.overwrite(bitstring.BitString(bin='1'*128), offset)
    test_roundtrip(response_sequence)
  return

def trigger_challenge_algorithm():
  test_roundtrip(instigat)
  response_sequence = onesssss.copy()
  def unexpected_output_action():
    return
  test_roundtrip(response_sequence)
  return

def sustain_the_challenge():
   def unexpected_output_action(test_bytes):
      return False
   clock_in_clock_out(instigat, instigat, single_clk_pulse, unexpected_output_action, logging_serial_handler)
   clock_in_clock_out(instigat, instigat, single_clk_pulse, unexpected_output_action, logging_serial_handler)
   return

def try_all_challenges():
  for frame_responder in [get_offset_responder(384-24), get_offset_responder(384)]: # [get_setbit_responder(instigat), get_setbit_responder(sd_alone), get_setbit_responder(sd_count), get_setbit_responder(sd_alone | sd_count), get_setbit_responder(instigat | sd_alone | sd_count), get_setbit_responder(blanksss),get_offset_responder(128), get_offset_responder(256), get_offset_responder(384)]:
    for variant_responder in [get_trivial_responder, get_rev_responder, get_swp_responder, get_swprev_responder]:
        for password_prepare in [pad_password, md5_password]:
           for operation in [encrypt, decrypt]:
              for cipher in [aes_ecb, aes_ctr, aes_cbc]:
                 try_responses(password_prepare, variant_responder(get_cipher_message_responder(operation, cipher)), frame_responder, name=str(password_prepare)+str(variant_responder)+str(operation)+str(cipher)+str(frame_responder))
        for password_prepare in [trivial, pad_password]:
           for message_responder in [hmacmd5, md5concat]:
                 try_responses(password_prepare, variant_responder(message_responder), frame_responder, name=str(password_prepare)+str(variant_responder)+str(message_responder)+str(frame_responder))
        for password_prepare in [pad_password]:
           try_responses(password_prepare, variant_responder(xor), frame_responder,name=str(password_prepare)+str(variant_responder)+str(xor)+str(frame_responder) )
  return

def try_suggested_challenges():
  for frame_responder in [get_offset_ored_responder(384-24), get_offset_ored_responder(128), get_offset_ored_responder(0)]:
    for variant_responder in [get_bitswapped_responder, get_rev_bitswapped_responder, get_rev_responder]:
        for password_prepare in [pad_password, md5_password]:
           for operation in [encrypt, decrypt]:
              for cipher in [aes_ecb]:
                 try_responses(password_prepare, variant_responder(get_cipher_message_responder(operation, cipher)), frame_responder, name=str(password_prepare)+str(variant_responder)+str(operation)+str(cipher)+str(frame_responder))
        for password_prepare in [trivial, pad_password]:
           for message_responder in [hmacmd5, md5concat]:
                 try_responses(password_prepare, variant_responder(message_responder), frame_responder, name=str(password_prepare)+str(variant_responder)+str(message_responder)+str(frame_responder))
  return

def try_jb_challenges():
  for i in range(0,512-128-24):
    frame_responder = get_offset_responder(i)
    for variant_responder in [get_rev_responder, get_bitswapped_responder, get_rev_bitswapped_responder]:
        for password_prepare in [pad_password]:
           for operation in [encrypt, decrypt]:
              for cipher in [aes_ecb]:
                 try_responses(password_prepare, variant_responder(get_cipher_message_responder(operation, cipher)), frame_responder, name=str(password_prepare)+str(variant_responder)+str(operation)+str(cipher)+str(frame_responder))
  return

def try_aes_challenges():
  for frame_responder in [get_offset_ored_responder(356), get_offset_ored_responder(356-128), get_offset_responder(512-128-25-128)]:
    for variant_responder in [get_rev_responder, get_bitswapped_responder, get_rev_bitswapped_responder]:
        for password_prepare in [ssl_password, pad_password]:
           for operation in [encrypt, decrypt]:
              for cipher in [aes_ecb]:
                 try_responses(password_prepare, variant_responder(get_cipher_message_responder(operation, cipher)), frame_responder, name=str(password_prepare)+str(variant_responder)+str(operation)+str(cipher)+str(frame_responder))
  return

def try_just128bit_experiment():
  #release_reset_and_wait()
  serial_handler = logging_serial_handler

  frameA_rx = quick_instigate_challenge(serial_handler)
  if frameA_rx is None:
    return None

  frameB1_rx = single_frame_send_and_receive(bitstring.BitString(hex='00'*16))
  if not get_and_handle_serial(serial_handler):
    return None

  frameB2_rx = single_frame_send_and_receive(bitstring.BitString(hex='CC'*16))
  if not get_and_handle_serial(serial_handler):
    return None

  log("end frame")
  single_clk_pulse()
  if not get_and_handle_serial(serial_handler):
    return None

  frameC_rx = quick_instigate_challenge(serial_handler)
  if frameC_rx is None:
    return None

  frameD1_rx = single_frame_send_and_receive(bitstring.BitString(hex='00'*16))
  if not get_and_handle_serial(serial_handler):
    return None

  frameD2_rx = single_frame_send_and_receive(bitstring.BitString(hex='CC'*16))
  if not get_and_handle_serial(serial_handler):
    return None

  log("end frame")
  single_clk_pulse()
  if not get_and_handle_serial(serial_handler):
    return None
  return

def explore_frames_shiftdepth():
  serial_handler = logging_serial_handler

  sentinel = bitstring.BitString(hex='DEFEA7ED55555555555555555555555555555555')

  enable_shift()
  rx = shift_in_and_out_sequence_until(sentinel)
  log("frameA shift depth: %d" % (rx.len - sentinel.len))
  get_and_handle_serial(serial_handler)
  shift_in_and_out_sequence(instigat[-160:]) #quick instigate
  disable_shift()
  single_clk_pulse()
  get_and_handle_serial(serial_handler)

  enable_shift()
  rx = shift_in_and_out_sequence_until(sentinel)
  get_and_handle_serial(serial_handler)
  log("frameB shift depth: %d" % (rx.len - sentinel.len))
  disable_shift()
  single_clk_pulse()
  get_and_handle_serial(serial_handler)

  enable_shift()
  rx = shift_in_and_out_sequence_until(sentinel)
  get_and_handle_serial(serial_handler)
  log("frameC shift depth: %d" % (rx.len - sentinel.len))
  disable_shift()
  single_clk_pulse()
  get_and_handle_serial(serial_handler)

  return

def guess_frameB_auth_bit():
  serial_handler = logging_serial_handler

  enable_shift()
  shift_in_and_out_sequence(instigat[-160:]) #quick instigate
  disable_shift()
  single_clk_pulse()
  get_and_handle_serial(serial_handler)

  trailer=bitstring.BitString(hex='55555555555555555555555555555555DEFEA7ED')
  test_bit = bitstring.BitString(bin='0'*512)
  test_bit.overwrite(trailer, 512-trailer.len)
  enable_shift()
  rx = shift_in_and_out_sequence(test_bit)
  disable_shift()
  single_clk_pulse()
  get_and_handle_serial(serial_handler)

  sleep(1)
  get_and_handle_serial(serial_handler)
  return

def explore_frameB_bits():
  serial_handler = logging_serial_handler

  for bit in range(512-128, 0, -1):
    release_reset_and_wait()
    enable_shift()
    shift_in_and_out_sequence(instigat[-160:]) #quick instigate
    disable_shift()
    log("end frame")
    single_clk_pulse()
    get_and_handle_serial(serial_handler)

    test_bit = bitstring.BitString(bin='0'*512)
    test_bit.set(1, [bit])
    enable_shift()
    rx = shift_in_and_out_sequence(test_bit)
    disable_shift()
    log("end frame")
    single_clk_pulse()
    get_and_handle_serial(serial_handler)

    enable_shift()
    shift_in_and_out_sequence(blanksss)
    disable_shift()
    log("end frame")
    single_clk_pulse()
    get_and_handle_serial(serial_handler)
  return

def explore_frameB_stuckbits():
  serial_handler = logging_serial_handler

  enable_shift()
  shift_in_and_out_sequence(instigat[-160:]) #quick instigate
  disable_shift()
  log("end frame")
  single_clk_pulse()
  get_and_handle_serial(serial_handler)

  test_bit = bitstring.BitString(bin='1'*512)
  test_bit &= ~(sd_count|sd_alone|instigat|authicat)

  enable_shift()
  shift_in_and_out_sequence(test_bit)
  disable_shift()
  log("end frame")
  single_clk_pulse()
  get_and_handle_serial(serial_handler)

  enable_shift()
  actual_bit=shift_in_and_out_sequence(blanksss)
  disable_shift()
  log("end frame")
  single_clk_pulse()
  get_and_handle_serial(serial_handler)

  log("stuck bits: %s" % (test_bit ^ actual_bit).hex)

  return

def explore_auth_failed():
  serial_handler = logging_serial_handler

  enable_shift()
  shift_in_and_out_sequence((instigat)[-160:]) #quick instigate
  disable_shift()
  log("end frame")
  single_clk_pulse()
  get_and_handle_serial(serial_handler)

#  test_bit = bitstring.BitString(bin='1'*512)
#  test_bit &= ~(sd_count|sd_alone|instigat|authicat|b_stuck)
#  test_bit |= authicat

  test_bit = bitstring.BitString(bin='0'*512)
  test_bit |= authicat
  test_bit.overwrite(bitstring.BitString(bin='1'*128), 0)

  enable_shift()
  shift_in_and_out_sequence(bitstring.BitString(bin='0'*128))
  shift_in_and_out_sequence(test_bit)
  disable_shift()
  log("end frame")
  single_clk_pulse()
  get_and_handle_serial(serial_handler)

  enable_shift()
  actual_bit=shift_in_and_out_sequence(blanksss)
  disable_shift()
  log("end frame")
  single_clk_pulse()
  get_and_handle_serial(serial_handler)

  return

def explore_repeat_frameA_nochallenge():
  serial_handler = logging_serial_handler

  while True:
    enable_shift()
    shift_in_and_out_sequence(((blanksss))[-160:]) #quick instigate
    disable_shift()
    log("end frame")
    pin_high(TRIG_OUT)
    single_clk_pulse()
    pin_low(TRIG_OUT)
    get_and_handle_serial(serial_handler)
    sleep(2)
  return

def explore_repeat_frameB_auth_failed():
  serial_handler = logging_serial_handler

  while True:
    enable_shift()
    shift_in_and_out_sequence((instigat)[-160:]) #quick instigate
    disable_shift()
    log("end frame")
    single_clk_pulse()
    get_and_handle_serial(serial_handler)

    test_bit = instigat.copy()[-160:]

    enable_shift()
    shift_in_and_out_sequence(instigat[-160:])
    shift_in_and_out_sequence(test_bit)
    disable_shift()
    log("end frame")
    pin_high(TRIG_OUT)
    single_clk_pulse()
    pin_low(TRIG_OUT)
    get_and_handle_serial(serial_handler)
    sleep(2)

  return

def try_frameB_response(password_bytes, password_prepare, message_responder, frame_responder, name=None):
  serial_handler = reset_on_sd_serial_handler
  serial_output = bytearray(b'')

  if name is None:
    name = str(password_bytes)+str(password_prepare)+str(message_responder)

  log("\n%s" % name)

  frameA_rx = quick_instigate_challenge(serial_handler)
  if frameA_rx is None:
    return None

  challenge_sequence = single_frame_send_and_receive(bitstring.BitString(hex='00'*16))
  ok, line = get_and_handle_serial(serial_handler)
  if not ok:
    return None
  serial_output.extend(line)
  log("challenge:  %s" % challenge_sequence.hex)

  password_sequence = password_prepare(bitstring.BitString(password_bytes))
  log("password prepared :  %s" % password_sequence.hex)

  message_response_sequence = message_responder(password_sequence, challenge_sequence)
  log("response :  %s" % message_response_sequence.hex)
  frame_response_sequence = frame_responder(message_response_sequence, challenge_sequence)


  pin_high(TRIG_OUT) # interesting stuff happens in frameB here

  single_frame_send_and_receive(frame_response_sequence)
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

  if len(serial_output.decode('utf-8').strip(' \t\n\r')) == 0:
    log("WARNING: no output on serial")

  if ((not 'Authentication failed' in serial_output.decode('utf-8')) and (not 'Self-destruct triggered' in serial_output.decode('utf-8'))) or (result_sequence != blanksss):
    log("=====================================================================================")
    log("FLAG (???)")
    log("result   : %s" % result_sequence.hex)
    log("=====================================================================================")
    with open('flags.txt', 'a') as the_file:
      the_file.write("\n%s\n" % name)
      the_file.write("challenge: %s\n" % challenge_sequence.hex)
      the_file.write("response : %s\n" % message_response_sequence.hex)
      the_file.write("result   : %s\n" % result_sequence.hex)
      the_file.write("serial   : %s\n" % serial_output)
  return

def try_frameB_quadD_responses(passwords, password_prepare, message_responder, name=None):
  frame_responder = get_quadD_andauth_responder()
  serial_handler = reset_on_sd_serial_handler
  serial_output = bytearray(b'')

  if name is None:
    name = str(password_bytes)+str(password_prepare)+str(message_responder)

  initiated = False
  for password_bytes in passwords:
    log("\n%s%s" % (password_bytes, name))

    if not initiated:
      frameA_rx = quick_instigate_challenge(serial_handler)
      if frameA_rx is None:
        return None

      challenge_sequence = single_frame_send_and_receive(bitstring.BitString(hex='00'*16))
      initiated = True
      ok, line = get_and_handle_serial(serial_handler)
      if not ok:
        return None
      serial_output.extend(line)
      log("challenge:  %s" % challenge_sequence.hex)
    else:
      log("reuse previous challenge: %s" % challenge_sequence.hex)

    password_sequence = password_prepare(bitstring.BitString(password_bytes))
    log("password prepared:  %s" % password_sequence.hex)

    message_response_sequence = message_responder(password_sequence, challenge_sequence)
    if message_response_sequence & (sd_alone | sd_count)[-128:]:
      log("skipping self-destruct response: %s" % message_response_sequence.hex)
      initiated = True # not needed, but reminds us we need to try again without re-initiating a challenge
      continue

    log("response :  %s" % message_response_sequence.hex)
    frame_response_sequence = frame_responder(message_response_sequence, challenge_sequence)

    single_frame_send_and_receive(frame_response_sequence)
    ok, line = get_and_handle_serial(serial_handler)
    if not ok:
      return None
    serial_output.extend(line)

    log("end frame")
    single_clk_pulse()

    initiated = False
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

    if len(serial_output.decode('utf-8').strip(' \t\n\r')) == 0:
      log("WARNING: no output on serial")

    if ((not 'Authentication failed' in serial_output.decode('utf-8')) and (not 'Self-destruct triggered' in serial_output.decode('utf-8'))) or (result_sequence != blanksss):
      log("=====================================================================================")
      log("FLAG (???)")
      log("result   : %s" % result_sequence.hex)
      log("=====================================================================================")
      with open('flags.txt', 'a') as the_file:
        the_file.write("\n%s\n" % name)
        the_file.write("challenge: %s\n" % challenge_sequence.hex)
        the_file.write("response : %s\n" % message_response_sequence.hex)
        the_file.write("result   : %s\n" % result_sequence.hex)
        the_file.write("serial   : %s\n" % serial_output)
  return

def try_all_aes_frameB_challenges():
  for argsorder_responder in [get_trivial_responder, get_swp_responder]:
    for password_prepare in [pad_password, ssl_password, md5_password]:
      for frame_responder in [get_quadA_andauth_responder(), get_quadB_andauth_responder()]:
        for variant_responder in [get_rev_responder, get_bitswapped_responder, get_rev_bitswapped_responder, get_trivial_responder]:
          for operation in [encrypt, decrypt]:
            for cipher in [aes_ecb]:
              for password in passwords:
                try_frameB_response(password, password_prepare, variant_responder(argsorder_responder(get_cipher_message_responder(operation, cipher))), frame_responder, name=str(password)+str(password_prepare)+str(variant_responder)+str(argsorder_responder)+str(operation)+str(cipher)+str(frame_responder))
  return

def try_aes_frameB_challenges():
  for frame_responder in [get_quadA_andauth_responder()]:
    for variant_responder in [get_rev_responder, get_bitswapped_responder, get_rev_bitswapped_responder, get_trivial_responder]:
        for password_prepare in [pad_password, ssl_password2, ssl_password, md5_password]:
           for operation in [encrypt, decrypt]:
              for cipher in [aes_ecb]:
                for password in passwords:
                  try_frameB_response(password, password_prepare, variant_responder(get_cipher_message_responder(operation, cipher)), frame_responder, name=str(password)+str(password_prepare)+str(variant_responder)+str(operation)+str(cipher)+str(frame_responder))
  return

def continue_aes_frameB_challenges():
  for frame_responder in [get_quadA_andauth_responder()]:
    for variant_responder in [get_trivial_responder]:
        for password_prepare in [pad_password, ssl_password2, ssl_password, md5_password]:
           for operation in [encrypt, decrypt]:
              for cipher in [aes_ecb]:
                for password in passwords:
                  try_frameB_response(password, password_prepare, variant_responder(get_cipher_message_responder(operation, cipher)), frame_responder, name=str(password)+str(password_prepare)+str(variant_responder)+str(operation)+str(cipher)+str(frame_responder))
  for frame_responder in [get_quadB_andauth_responder()]:
    for variant_responder in [get_rev_responder, get_bitswapped_responder, get_rev_bitswapped_responder, get_trivial_responder]:
        for password_prepare in [pad_password, ssl_password2, ssl_password, md5_password]:
           for operation in [encrypt, decrypt]:
              for cipher in [aes_ecb]:
                for password in passwords:
                  try_frameB_response(password, password_prepare, variant_responder(get_cipher_message_responder(operation, cipher)), frame_responder, name=str(password)+str(password_prepare)+str(variant_responder)+str(operation)+str(cipher)+str(frame_responder))
  return

def continue_swapped_aes_frameB_challenges():
  for frame_responder in [get_quadB_andauth_responder(), get_quadA_andauth_responder()]:
    for variant_responder in [get_rev_responder, get_bitswapped_responder, get_rev_bitswapped_responder, get_trivial_responder]:
      for argsorder_responder in [get_swp_responder]: #get_trivial_responder
        for password_prepare in [pad_password, ssl_password2, ssl_password, md5_password]:
          for operation in [encrypt, decrypt]:
            for cipher in [aes_ecb]:
              for password in passwords:
                try_frameB_response(password, password_prepare, variant_responder(argsorder_responder(get_cipher_message_responder(operation, cipher))), frame_responder, name=str(password)+str(password_prepare)+str(variant_responder)+str(argsorder_responder)+str(operation)+str(cipher)+str(frame_responder))
  return

def try_frameB_quadD_guess_challenges():
  for argsorder_responder in [get_trivial_responder, get_swp_responder]:
    for password_prepare in [pad_password, ssl_password, md5_password]:
      for frame_responder in [get_quadD_andauth_responder()]:
        for variant_responder in [get_rev_responder, get_bitswapped_responder, get_rev_bitswapped_responder, get_trivial_responder]:
          for operation in [decrypt]:
            for cipher in [aes_ecb]:
              for password in passwords:
                try_frameB_response(password, password_prepare, variant_responder(argsorder_responder(get_cipher_message_responder(operation, cipher))), frame_responder, name=str(password)+str(password_prepare)+str(variant_responder)+str(argsorder_responder)+str(operation)+str(cipher)+str(frame_responder))
  return

def try_frameB_quadD_nosd_challenges():
  for argsorder_responder in [get_trivial_responder, get_swp_responder]:
    for password_prepare in [pad_password, ssl_password, md5_password]:
      for variant_responder in [get_rev_responder, get_bitswapped_responder, get_rev_bitswapped_responder, get_trivial_responder]:
        for operation in [decrypt, encrypt]:
          for cipher in [aes_ecb]:
            try_frameB_quadD_responses(passwords, password_prepare, variant_responder(argsorder_responder(get_cipher_message_responder(operation, cipher))), str(argsorder_responder.__name__)+'/'+str(password_prepare.__name__)+'/'+str(variant_responder.__name__)+'/'+str(operation.__name__)+'/'+str(cipher.__name__))
  return

def try_aes_frameB_pairs_challenges_bestguess():
  attempts = list()
  for frame_responder in [get_quadA_andauth_responder()]:
    for variant_responder in [get_rev_responder, get_trivial_responder, get_bitswapped_responder, get_rev_bitswapped_responder]:
        for password_prepare in [pad_password]:
           for operation in [encrypt, decrypt]:
              for cipher in [aes_ecb]:
                for password in get_16byte_pair_passwords():
                  attempts.append([password, password_prepare, variant_responder, operation, cipher, frame_responder])

  #start at quadA_responder/get_trivial_responder/pad_password/encrypt/aes_ecb/b'iloveyoustarwars'
  #start = 413
  #backdoorstarwars etc
  #start = 768

  for i in range(start, len(attempts)):
    password, password_prepare, variant_responder, operation, cipher, frame_responder = attempts[i]
    log("%d of %d" %(i, len(attempts)))
    try_frameB_response(password, password_prepare, variant_responder(get_cipher_message_responder(operation, cipher)), frame_responder, name=str(frame_responder.__name__)+'/'+str(variant_responder.__name__)+'/'+str(password_prepare.__name__)+'/'+str(operation.__name__)+'/'+str(cipher.__name__)+'/'+str(password))
    i = i + 1

  return


def try_aes_frameB_pairs_challenges_therest():
  attempts = list()

  for frame_responder in [get_quadA_andauth_responder()]:
    for variant_responder in [get_rev_responder, get_trivial_responder, get_bitswapped_responder, get_rev_bitswapped_responder]:
      for argsorder_responder in [get_trivial_responder, get_swp_responder]:
        for password_prepare in [pad_password]:
          for operation in [encrypt, decrypt]:
            for cipher in [aes_ecb]:
              for password in get_16byte_pair_password_repeats():
                attempts.append([password, password_prepare, variant_responder, argsorder_responder, operation, cipher, frame_responder])
  for frame_responder in [get_quadB_andauth_responder()]:
    for variant_responder in [get_rev_responder, get_trivial_responder, get_bitswapped_responder, get_rev_bitswapped_responder]:
      for argsorder_responder in [get_trivial_responder, get_swp_responder]:
        for password_prepare in [pad_password]:
          for operation in [encrypt, decrypt]:
            for cipher in [aes_ecb]:
              passwords = get_16byte_pair_passwords()
              passwords.extend(get_16byte_pair_password_repeats())
              for password in passwords:
                attempts.append([password, password_prepare, variant_responder, argsorder_responder, operation, cipher, frame_responder])

  #for argsorder_responder in [get_trivial_responder, get_swp_responder]:
  #  for variant_responder in [get_rev_responder, get_trivial_responder, get_bitswapped_responder, get_rev_bitswapped_responder]:
  #      for password_prepare in [pad_password]:
  #         for operation in [encrypt, decrypt]:
  #            for cipher in [aes_ecb]:
  #              passwords = get_16byte_pair_passwords()
  #              passwords.extend(get_16byte_pair_password_repeats())
  #              try_frameB_quadD_responses(passwords, password_prepare, variant_responder(argsorder_responder(get_cipher_message_responder(operation, cipher))), str(argsorder_responder.__name__)+'/'+str(password_prepare.__name__)+'/'+str(variant_responder.__name__)+'/'+str(operation.__name__)+'/'+str(cipher.__name__))

  start = 2050
  for i in range(start, len(attempts)):
    password, password_prepare, variant_responder, argsorder_responder, operation, cipher, frame_responder = attempts[i]
    log("%d of %d" %(i, len(attempts)))
    try_frameB_response(password, password_prepare, variant_responder(argsorder_responder(get_cipher_message_responder(operation, cipher))), frame_responder, name=str(frame_responder.__name__)+'/'+str(variant_responder.__name__)+'/'+str(argsorder_responder.__name__)+'/'+str(password_prepare.__name__)+'/'+str(operation.__name__)+'/'+str(cipher.__name__)+'/'+str(password))
    i = i + 1

  return

def try_aes_frameB_pairs_challenges_justdoitallagain():
  attempts = list()

  for frame_responder in [get_quadA_andauth_responder(), get_quadB_andauth_responder()]:
    for variant_responder in [get_rev_responder, get_trivial_responder, get_bitswapped_responder, get_rev_bitswapped_responder]:
      for argsorder_responder in [get_trivial_responder, get_swp_responder]:
        for password_prepare in [pad_password]:
          for operation in [encrypt, decrypt]:
            for cipher in [aes_ecb]:
              passwords = get_16byte_pair_passwords()
              passwords.extend(get_16byte_pair_password_repeats())
              for password in passwords:
                attempts.append([password, password_prepare, variant_responder, argsorder_responder, operation, cipher, frame_responder])

  start = 1187
  for i in range(start, len(attempts)):
    password, password_prepare, variant_responder, argsorder_responder, operation, cipher, frame_responder = attempts[i]
    log("%d of %d" %(i, len(attempts)))
    try_frameB_response(password, password_prepare, variant_responder(argsorder_responder(get_cipher_message_responder(operation, cipher))), frame_responder, name=str(frame_responder.__name__)+'/'+str(variant_responder.__name__)+'/'+str(argsorder_responder.__name__)+'/'+str(password_prepare.__name__)+'/'+str(operation.__name__)+'/'+str(cipher.__name__)+'/'+str(password))
    i = i + 1

  for argsorder_responder in [get_trivial_responder, get_swp_responder]:
    for variant_responder in [get_rev_responder, get_trivial_responder, get_bitswapped_responder, get_rev_bitswapped_responder]:
        for password_prepare in [pad_password]:
           for operation in [encrypt, decrypt]:
              for cipher in [aes_ecb]:
                passwords = get_16byte_pair_passwords()
                passwords.extend(get_16byte_pair_password_repeats())
                try_frameB_quadD_responses(passwords, password_prepare, variant_responder(argsorder_responder(get_cipher_message_responder(operation, cipher))), str(get_quadD_andauth_responder().__name__)+'/'+str(argsorder_responder.__name__)+'/'+str(password_prepare.__name__)+'/'+str(variant_responder.__name__)+'/'+str(operation.__name__)+'/'+str(cipher.__name__))

  return

def try_aes_frameB_pairs_challenges_trymorebitswapsandcmac():
  attempts = list()

  for frame_responder in [get_quadA_andauth_responder(), get_quadB_andauth_responder()]:
    for variant_responder in [get_rev_responder, get_trivial_responder, get_bitswapped_responder, get_rev_bitswapped_responder, get_wordbitswapped_responder, get_rev_wordbitswapped_responder, get_longbitswapped_responder, get_rev_longbitswapped_responder]:
      for argsorder_responder in [get_trivial_responder, get_swp_responder]:
        for password_prepare in [pad_password]:
              passwords = get_16byte_pair_passwords()
              passwords.extend(get_16byte_pair_password_repeats())
              for password in passwords:
                attempts.append([password, password_prepare, variant_responder(argsorder_responder(aes_cmac)), frame_responder, str(frame_responder.__name__)+'/'+str(variant_responder.__name__)+'/'+str(argsorder_responder.__name__)+'/'+str(password_prepare.__name__)+'/'+str(aes_cmac.__name__)+'/'+str(password)])

  for frame_responder in [get_quadA_andauth_responder(), get_quadB_andauth_responder()]:
    for variant_responder in [get_wordbitswapped_responder, get_rev_wordbitswapped_responder, get_longbitswapped_responder, get_rev_longbitswapped_responder]:
      for argsorder_responder in [get_trivial_responder, get_swp_responder]:
        for password_prepare in [pad_password]:
          for operation in [encrypt, decrypt]:
            for cipher in [aes_ecb]:
              passwords = get_16byte_pair_passwords()
              passwords.extend(get_16byte_pair_password_repeats())
              for password in passwords:
                attempts.append([password, password_prepare, variant_responder(argsorder_responder(get_cipher_message_responder(operation, cipher))), frame_responder, str(frame_responder.__name__)+'/'+str(variant_responder.__name__)+'/'+str(argsorder_responder.__name__)+'/'+str(password_prepare.__name__)+'/'+str(operation.__name__)+'/'+str(cipher.__name__)+'/'+str(password)])

  start = 0
  for i in range(start, len(attempts)):
    password, password_prepare, message_responder, frame_responder, name = attempts[i]
    log("%d of %d" %(i, len(attempts)))
    try_frameB_response(password, password_prepare, message_responder, frame_responder, name=name)
    i = i + 1

  for argsorder_responder in [get_trivial_responder, get_swp_responder]:
    for variant_responder in [get_wordbitswapped_responder, get_rev_wordbitswapped_responder, get_longbitswapped_responder, get_rev_longbitswapped_responder]:
        for password_prepare in [pad_password]:
           for operation in [encrypt, decrypt]:
              for cipher in [aes_ecb]:
                passwords = get_16byte_pair_passwords()
                passwords.extend(get_16byte_pair_password_repeats())
                try_frameB_quadD_responses(passwords, password_prepare, variant_responder(argsorder_responder(get_cipher_message_responder(operation, cipher))), str(get_quadD_andauth_responder().__name__)+'/'+str(argsorder_responder.__name__)+'/'+str(password_prepare.__name__)+'/'+str(variant_responder.__name__)+'/'+str(operation.__name__)+'/'+str(cipher.__name__))

  return

def try_aes_frameB_pairs_challenges_tryrepeatingchallenge():
  attempts = list()

  for frame_responder in [get_quadB_andauth_responder()]:
    for variant_responder in [get_rev_responder, get_trivial_responder, get_bitswapped_responder, get_rev_bitswapped_responder, get_wordbitswapped_responder, get_rev_wordbitswapped_responder, get_longbitswapped_responder, get_rev_longbitswapped_responder]:
      for argsorder_responder in [get_trivial_responder, get_swp_responder]:
        for password_prepare in [pad_password]:
              passwords = get_16byte_pair_passwords()
              passwords.extend(get_16byte_pair_password_repeats())
              for password in passwords:
                attempts.append([password, password_prepare, variant_responder(argsorder_responder(aes_cmac)), frame_responder, str(frame_responder.__name__)+'/'+str(variant_responder.__name__)+'/'+str(argsorder_responder.__name__)+'/'+str(password_prepare.__name__)+'/'+str(aes_cmac.__name__)+'/'+str(password)])

  for frame_responder in [get_quadB_andauth_responder()]:
    for variant_responder in [get_rev_responder, get_trivial_responder, get_bitswapped_responder, get_rev_bitswapped_responder, get_wordbitswapped_responder, get_rev_wordbitswapped_responder, get_longbitswapped_responder, get_rev_longbitswapped_responder]:
      for argsorder_responder in [get_trivial_responder, get_swp_responder]:
        for password_prepare in [pad_password]:
          for operation in [encrypt, decrypt]:
            for cipher in [aes_ecb]:
              passwords = get_16byte_pair_passwords()
              passwords.extend(get_16byte_pair_password_repeats())
              for password in passwords:
                attempts.append([password, password_prepare, variant_responder(argsorder_responder(get_cipher_message_responder(operation, cipher))), frame_responder, str(frame_responder.__name__)+'/'+str(variant_responder.__name__)+'/'+str(argsorder_responder.__name__)+'/'+str(password_prepare.__name__)+'/'+str(operation.__name__)+'/'+str(cipher.__name__)+'/'+str(password)])

  start = 0
  for i in range(start, len(attempts)):
    password, password_prepare, message_responder, frame_responder, name = attempts[i]
    log("%d of %d" %(i, len(attempts)))
    try_frameB_response(password, password_prepare, message_responder, frame_responder, name=name)
    i = i + 1
  return

def try_startrekstarwars_anomaly():
  attempts = list()
  for frame_responder in [get_quadA_andauth_responder()]:
    for variant_responder in [get_trivial_responder]:
      for argsorder_responder in [get_trivial_responder]:
        for password_prepare in [pad_password]:
          for operation in [encrypt]:
            for cipher in [aes_ecb]:
              for password in [b'startrekstarwars']:
                attempts.append([password, password_prepare, variant_responder(argsorder_responder(get_cipher_message_responder(operation, cipher))), frame_responder, str(frame_responder.__name__)+'/'+str(variant_responder.__name__)+'/'+str(argsorder_responder.__name__)+'/'+str(password_prepare.__name__)+'/'+str(operation.__name__)+'/'+str(cipher.__name__)+'/'+str(password)])

  while True:
    start = 0
    for i in range(start, len(attempts)):
      password, password_prepare, message_responder, frame_responder, name = attempts[i]
      log("%d of %d" %(i, len(attempts)))
      try_frameB_response(password, password_prepare, message_responder, frame_responder, name=name)
      i = i + 1
  return

def try_frameB_quadA_againagain():
  attempts = list()

  for frame_responder in [get_quadA_andauth_responder()]:
    for variant_responder in [get_rev_responder, get_trivial_responder]:
      for argsorder_responder in [get_trivial_responder, get_swp_responder]:
        for password_prepare in [pad_password]:
          for operation in [encrypt, decrypt]:
            for cipher in [aes_ecb]:
              passwords = get_16byte_pair_passwords()
              passwords.extend(get_16byte_pair_password_repeats())
              for password in passwords:
                attempts.append([password, password_prepare, variant_responder(argsorder_responder(get_cipher_message_responder(operation, cipher))), frame_responder, str(frame_responder.__name__)+'/'+str(variant_responder.__name__)+'/'+str(argsorder_responder.__name__)+'/'+str(password_prepare.__name__)+'/'+str(operation.__name__)+'/'+str(cipher.__name__)+'/'+str(password)])
                attempts.append([password, password_prepare, variant_responder(argsorder_responder(aes_cmac)), frame_responder, str(frame_responder.__name__)+'/'+str(variant_responder.__name__)+'/'+str(argsorder_responder.__name__)+'/'+str(password_prepare.__name__)+'/'+str(aes_cmac.__name__)+'/'+str(password)])

  start = 0
  for i in range(start, len(attempts)):
    password, password_prepare, message_responder, frame_responder, name = attempts[i]
    log("%d of %d" %(i, len(attempts)))
    try_frameB_response(password, password_prepare, message_responder, frame_responder, name=name)
    i = i + 1
  return

def try_frameB_offsets_bestguesses():
  attempts = list()

  for offset in [203, 200, 202, 204, 201]:
    frame_responder = get_offet_and_auth_responder(offset)
    for variant_responder in [get_rev_responder, get_trivial_responder]:
      for argsorder_responder in [get_trivial_responder, get_swp_responder]:
        for password_prepare in [pad_password]:
          for operation in [decrypt]:
            for cipher in [aes_ecb]:
              passwords = get_16byte_pair_passwords()
              passwords.extend(get_16byte_pair_password_repeats())
              for password in passwords:
                attempts.append([password, password_prepare, variant_responder(argsorder_responder(get_cipher_message_responder(operation, cipher))), frame_responder, str(frame_responder.__name__)+'(%d' % offset +')'+'/'+str(variant_responder.__name__)+'/'+str(argsorder_responder.__name__)+'/'+str(password_prepare.__name__)+'/'+str(operation.__name__)+'/'+str(cipher.__name__)+'/'+str(password)])

  start = 0
  for i in range(start, len(attempts)):
    password, password_prepare, message_responder, frame_responder, name = attempts[i]
    log("%d of %d" %(i, len(attempts)))
    try_frameB_response(password, password_prepare, message_responder, frame_responder, name=name)
    i = i + 1
  return

def try_frameB_offsets_therest():
  attempts = list()

  for offset in [208, 192]:
    frame_responder = get_lsb_offet_and_auth_responder(offset)
    for variant_responder in [get_rev_responder, get_trivial_responder]:
      for argsorder_responder in [get_trivial_responder]:
        for password_prepare in [pad_password]:
          for operation in [decrypt]:
            for cipher in [aes_ecb]:
              passwords = get_16byte_pair_passwords()
              passwords.extend(get_16byte_pair_password_repeats())
              for password in passwords:
                attempts.append([password, password_prepare, variant_responder(argsorder_responder(get_cipher_message_responder(operation, cipher))), frame_responder, str(frame_responder.__name__)+'(%d' % offset +')'+'/'+str(variant_responder.__name__)+'/'+str(argsorder_responder.__name__)+'/'+str(password_prepare.__name__)+'/'+str(operation.__name__)+'/'+str(cipher.__name__)+'/'+str(password)])


  for offset in [203, 200, 202, 204, 208, 192]:
    frame_responder = get_msb_offet_and_auth_responder(offset)
    for variant_responder in [get_rev_responder, get_trivial_responder, get_bitswapped_responder, get_rev_bitswapped_responder]:
      for argsorder_responder in [get_trivial_responder]:
        for password_prepare in [pad_password]:
          for operation in [decrypt]:
            for cipher in [aes_ecb]:
              passwords = get_16byte_pair_passwords()
              passwords.extend(get_16byte_pair_password_repeats())
              for password in passwords:
                attempts.append([password, password_prepare, variant_responder(argsorder_responder(get_cipher_message_responder(operation, cipher))), frame_responder, str(frame_responder.__name__)+'(%d' % offset +')'+'/'+str(variant_responder.__name__)+'/'+str(argsorder_responder.__name__)+'/'+str(password_prepare.__name__)+'/'+str(operation.__name__)+'/'+str(cipher.__name__)+'/'+str(password)])

  for offset in [203, 200, 202, 204, 201]:
    frame_responder = get_lsb_offet_and_auth_responder(offset)
    for variant_responder in [get_bitswapped_responder, get_rev_bitswapped_responder]:
      for argsorder_responder in [get_trivial_responder]:
        for password_prepare in [pad_password]:
          for operation in [decrypt]:
            for cipher in [aes_ecb]:
              passwords = get_16byte_pair_passwords()
              passwords.extend(get_16byte_pair_password_repeats())
              for password in passwords:
                attempts.append([password, password_prepare, variant_responder(argsorder_responder(get_cipher_message_responder(operation, cipher))), frame_responder, str(frame_responder.__name__)+'(%d' % offset +')'+'/'+str(variant_responder.__name__)+'/'+str(argsorder_responder.__name__)+'/'+str(password_prepare.__name__)+'/'+str(operation.__name__)+'/'+str(cipher.__name__)+'/'+str(password)])

  start = 0
  for i in range(start, len(attempts)):
    password, password_prepare, message_responder, frame_responder, name = attempts[i]
    log("%d of %d" %(i, len(attempts)))
    try_frameB_response(password, password_prepare, message_responder, frame_responder, name=name)
    i = i + 1
  return

def try_frameB_offsets_dontforget196():
  attempts = list()

  for offset in [196]:
    frame_responder = get_msb_offet_and_auth_responder(offset)
    for variant_responder in [get_rev_responder, get_trivial_responder, get_bitswapped_responder, get_rev_bitswapped_responder]:
      for argsorder_responder in [get_trivial_responder]:
        for password_prepare in [pad_password]:
          for operation in [decrypt]:
            for cipher in [aes_ecb]:
              passwords = get_16byte_pair_passwords()
              passwords.extend(get_16byte_pair_password_repeats())
              for password in passwords:
                attempts.append([password, password_prepare, variant_responder(argsorder_responder(get_cipher_message_responder(operation, cipher))), frame_responder, str(frame_responder.__name__)+'(%d' % offset +')'+'/'+str(variant_responder.__name__)+'/'+str(argsorder_responder.__name__)+'/'+str(password_prepare.__name__)+'/'+str(operation.__name__)+'/'+str(cipher.__name__)+'/'+str(password)])

  start = 0
  for i in range(start, len(attempts)):
    password, password_prepare, message_responder, frame_responder, name = attempts[i]
    log("%d of %d" %(i, len(attempts)))
    try_frameB_response(password, password_prepare, message_responder, frame_responder, name=name)
    i = i + 1
  return

def try_frameB_offsets_theotherway_bestguess():
  attempts = list()

  for offset in [512-203, 512-200, 512-201, 512-202, 512-199, 512-198, 512-196]:
    frame_responder = get_lsb_offet_and_auth_responder(offset)
    for variant_responder in [get_rev_responder, get_trivial_responder, get_bitswapped_responder, get_rev_bitswapped_responder]:
      for argsorder_responder in [get_trivial_responder]:
        for password_prepare in [pad_password]:
          for operation in [decrypt]:
            for cipher in [aes_ecb]:
              passwords = get_16byte_pair_passwords()
              passwords.extend(get_16byte_pair_password_repeats())
              for password in passwords:
                attempts.append([password, password_prepare, variant_responder(argsorder_responder(get_cipher_message_responder(operation, cipher))), frame_responder, str(frame_responder.__name__)+'(%d' % offset +')'+'/'+str(variant_responder.__name__)+'/'+str(argsorder_responder.__name__)+'/'+str(password_prepare.__name__)+'/'+str(operation.__name__)+'/'+str(cipher.__name__)+'/'+str(password)])

  start = 1587
  for i in range(start, len(attempts)):
    password, password_prepare, message_responder, frame_responder, name = attempts[i]
    log("%d of %d" %(i, len(attempts)))
    try_frameB_response(password, password_prepare, message_responder, frame_responder, name=name)
    i = i + 1
  return

mystery_sequence = bitstring.BitString(hex='00588384f9653e1719f34b517d928124')

def try_repeat_mystery_sequence():
    def mystery_sequence_responder(password_sequence, challenge_sequence):
      return mystery_sequence

    try_frameB_response(b'', pad_password, mystery_sequence_responder, get_lsb_offet_and_auth_responder(512-201), name='repeat mystery')
    return

def try_frameB_maybeflag():
  attempts = list()

  for offset in [512-201]:
    frame_responder = get_lsb_offet_and_auth_responder(offset)
    for variant_responder in [get_rev_responder]:
      for argsorder_responder in [get_trivial_responder]:
        for password_prepare in [pad_password]:
          for operation in [decrypt]:
            for cipher in [aes_ecb]:
                password = b'riscurinoletmein'
                attempts.append([password, password_prepare, variant_responder(argsorder_responder(get_cipher_message_responder(operation, cipher))), frame_responder, str(frame_responder.__name__)+'(%d' % offset +')'+'/'+str(variant_responder.__name__)+'/'+str(argsorder_responder.__name__)+'/'+str(password_prepare.__name__)+'/'+str(operation.__name__)+'/'+str(cipher.__name__)+'/'+str(password)])

  start = 0
  for i in range(start, len(attempts)):
    password, password_prepare, message_responder, frame_responder, name = attempts[i]
    log("%d of %d" %(i, len(attempts)))
    try_frameB_response(password, password_prepare, message_responder, frame_responder, name=name)
    i = i + 1
  return

def try_frameB_offsets_theotherway_remainder():
  attempts = list()

  for offset in range(512-160, 196, -4):
    frame_responder = get_lsb_offet_and_auth_responder(offset)
    for variant_responder in [get_rev_responder, get_trivial_responder]:
      for argsorder_responder in [get_trivial_responder]:
        for password_prepare in [pad_password]:
          for operation in [decrypt]:
            for cipher in [aes_ecb]:
              passwords = get_16byte_pair_passwords()
              passwords.extend(get_16byte_pair_password_repeats())
              for password in passwords:
                attempts.append([password, password_prepare, variant_responder(argsorder_responder(get_cipher_message_responder(operation, cipher))), frame_responder, str(frame_responder.__name__)+'(%d' % offset +')'+'/'+str(variant_responder.__name__)+'/'+str(argsorder_responder.__name__)+'/'+str(password_prepare.__name__)+'/'+str(operation.__name__)+'/'+str(cipher.__name__)+'/'+str(password)])

  start = 0
  for i in range(start, len(attempts)):
    password, password_prepare, message_responder, frame_responder, name = attempts[i]
    log("%d of %d" %(i, len(attempts)))
    try_frameB_response(password, password_prepare, message_responder, frame_responder, name=name)
    i = i + 1
  return

def try_frameB_offsets_theotherotherway_notdecryptnow():
  attempts = list()

  for offset in [76, 196, 200, 200-127]:
    frame_responder = get_msb_offet_and_auth_responder(offset)
    for variant_responder in [get_rev_responder, get_trivial_responder]:
      for argsorder_responder in [get_trivial_responder]:
        for password_prepare in [pad_password]:
          for operation in [encrypt]:
            for cipher in [aes_ecb]:
              passwords = get_16byte_pair_passwords()
              for password in passwords:
                attempts.append([password, password_prepare, variant_responder(argsorder_responder(get_cipher_message_responder(operation, cipher))), frame_responder, str(frame_responder.__name__)+'(%d' % offset +')'+'/'+str(variant_responder.__name__)+'/'+str(argsorder_responder.__name__)+'/'+str(password_prepare.__name__)+'/'+str(operation.__name__)+'/'+str(cipher.__name__)+'/'+str(password)])

  for offset in [76, 196, 200, 200-127]:
    frame_responder = get_msb_offet_and_auth_responder(offset)
    for variant_responder in [get_rev_responder, get_trivial_responder]:
      for argsorder_responder in [get_trivial_responder]:
        for password_prepare in [pad_password]:
          for operation in [encrypt]:
            for cipher in [aes_ecb]:
              passwords = get_16byte_pair_password_repeats()
              for password in passwords:
                attempts.append([password, password_prepare, variant_responder(argsorder_responder(get_cipher_message_responder(operation, cipher))), frame_responder, str(frame_responder.__name__)+'(%d' % offset +')'+'/'+str(variant_responder.__name__)+'/'+str(argsorder_responder.__name__)+'/'+str(password_prepare.__name__)+'/'+str(operation.__name__)+'/'+str(cipher.__name__)+'/'+str(password)])

  start = 0
  for i in range(start, len(attempts)):
    password, password_prepare, message_responder, frame_responder, name = attempts[i]
    log("%d of %d" %(i, len(attempts)))
    try_frameB_response(password, password_prepare, message_responder, frame_responder, name=name)
    i = i + 1
  return

def try_frameB_offsets_theotherotherway_notdecryptnow_therest():
  attempts = list()

  for offset in [200-7, 204-127, 204-7, 204, 202-127, 202-7, 202, 205-127, 205-7, 205, 201-127, 201-7, 201]:
    frame_responder = get_msb_offet_and_auth_responder(offset)
    for variant_responder in [get_rev_responder, get_trivial_responder]:
      for argsorder_responder in [get_trivial_responder]:
        for password_prepare in [pad_password]:
          for operation in [encrypt]:
            for cipher in [aes_ecb]:
              passwords = get_16byte_pair_passwords()
              passwords.extend(get_16byte_pair_password_repeats())
              for password in passwords:
                attempts.append([password, password_prepare, variant_responder(argsorder_responder(get_cipher_message_responder(operation, cipher))), frame_responder, str(frame_responder.__name__)+'(%d' % offset +')'+'/'+str(variant_responder.__name__)+'/'+str(argsorder_responder.__name__)+'/'+str(password_prepare.__name__)+'/'+str(operation.__name__)+'/'+str(cipher.__name__)+'/'+str(password)])

  start = 1998
  for i in range(start, len(attempts)):
    password, password_prepare, message_responder, frame_responder, name = attempts[i]
    log("%d of %d" %(i, len(attempts)))
    try_frameB_response(password, password_prepare, message_responder, frame_responder, name=name)
    i = i + 1
  return

def try_frameB_offsets_theotherotherway_notdecryptnow_lolwut():
  attempts = list()

  offsets=list()
  for candidate in [203, 202, 204, 201, 205]:
    offsets.append(candidate-127)
    offsets.append(candidate-7)
    offsets.append(candidate)

  for offset in offsets:
    frame_responder = get_msb_offet_and_auth_responder(offset)
    for variant_responder in [get_rev_responder, get_trivial_responder]:
      for argsorder_responder in [get_swp_responder]:
        for password_prepare in [pad_password]:
          for operation in [encrypt]:
            for cipher in [aes_ecb]:
              passwords = get_16byte_pair_passwords()
              passwords.extend(get_16byte_pair_password_repeats())
              for password in passwords:
                attempts.append([password, password_prepare, variant_responder(argsorder_responder(get_cipher_message_responder(operation, cipher))), frame_responder, str(frame_responder.__name__)+'(%d' % offset +')'+'/'+str(variant_responder.__name__)+'/'+str(argsorder_responder.__name__)+'/'+str(password_prepare.__name__)+'/'+str(operation.__name__)+'/'+str(cipher.__name__)+'/'+str(password)])

  for offset in offsets:
    frame_responder = get_msb_offet_and_auth_responder(offset)
    for variant_responder in [get_rev_responder, get_trivial_responder]:
      for argsorder_responder in [get_trivial_responder, get_swp_responder]:
        for password_prepare in [md5_password]:
          for operation in [encrypt]:
            for cipher in [aes_ecb]:
              passwords = get_16byte_pair_passwords()
              passwords.extend(get_16byte_pair_password_repeats())
              for password in passwords:
                attempts.append([password, password_prepare, variant_responder(argsorder_responder(get_cipher_message_responder(operation, cipher))), frame_responder, str(frame_responder.__name__)+'(%d' % offset +')'+'/'+str(variant_responder.__name__)+'/'+str(argsorder_responder.__name__)+'/'+str(password_prepare.__name__)+'/'+str(operation.__name__)+'/'+str(cipher.__name__)+'/'+str(password)])

  start = 10091
  for i in range(start, len(attempts)):
    password, password_prepare, message_responder, frame_responder, name = attempts[i]
    log("%d of %d" %(i, len(attempts)))
    try_frameB_response(password, password_prepare, message_responder, frame_responder, name=name)
    i = i + 1
  return

def try_frameB_forgottenoffsets_dumbencrypt():
  attempts = list()

  offsets = list()
  for candidate in [203, 202, 204]:
    offsets.append(candidate - 127+8)

  for offset in offsets:
    frame_responder = get_msb_offet_and_auth_responder(offset)
    for variant_responder in [get_rev_responder, get_trivial_responder]:
      for argsorder_responder in [get_trivial_responder, get_swp_responder]:
        for password_prepare in [pad_password]:
          for operation in [encrypt]:
            for cipher in [aes_ecb]:
              passwords = get_16byte_pair_passwords()
              passwords.extend(get_16byte_pair_password_repeats())
              for password in passwords:
                attempts.append([password, password_prepare, variant_responder(argsorder_responder(get_cipher_message_responder(operation, cipher))), frame_responder, str(frame_responder.__name__)+'(%d' % offset +')'+'/'+str(variant_responder.__name__)+'/'+str(argsorder_responder.__name__)+'/'+str(password_prepare.__name__)+'/'+str(operation.__name__)+'/'+str(cipher.__name__)+'/'+str(password)])

  start = 0
  for i in range(start, len(attempts)):
    password, password_prepare, message_responder, frame_responder, name = attempts[i]
    log("%d of %d" %(i, len(attempts)))
    try_frameB_response(password, password_prepare, message_responder, frame_responder, name=name)
    i = i + 1
  return

def try_frameB_offsets_letencrypt_ctr():
  attempts = list()

  offsets=list()
  for candidate in [203, 202, 204]:
    offsets.append(candidate-127)
    offsets.append(candidate-127+8)
    offsets.append(candidate-7)
    offsets.append(candidate)

  for offset in offsets:
    frame_responder = get_msb_offet_and_auth_responder(offset)
    for variant_responder in [get_rev_responder, get_trivial_responder]:
      for argsorder_responder in [get_trivial_responder, get_swp_responder]:
        for password_prepare in [pad_password]:
          for operation in [encrypt]:
            for cipher in [aes_ctr]:
              passwords = get_16byte_pair_passwords()
              passwords.extend(get_16byte_pair_password_repeats())
              for password in passwords:
                attempts.append([password, password_prepare, variant_responder(argsorder_responder(get_cipher_message_responder(operation, cipher))), frame_responder, str(frame_responder.__name__)+'(%d' % offset +')'+'/'+str(variant_responder.__name__)+'/'+str(argsorder_responder.__name__)+'/'+str(password_prepare.__name__)+'/'+str(operation.__name__)+'/'+str(cipher.__name__)+'/'+str(password)])

  start = 0
  for i in range(start, len(attempts)):
    password, password_prepare, message_responder, frame_responder, name = attempts[i]
    log("%d of %d" %(i, len(attempts)))
    try_frameB_response(password, password_prepare, message_responder, frame_responder, name=name)
    i = i + 1
  return

def try_frameB_moreoffsets_letencrypt_ctr():
  attempts = list()

  offsets = list(range(512-160-128, 75, -4))
  for candidate in [203]:
    offsets.remove(candidate-127)
    offsets.remove(candidate-127+8)
    offsets.remove(candidate-7)

  for offset in offsets:
    frame_responder = get_msb_offet_and_auth_responder(offset)
    for variant_responder in [get_rev_responder, get_trivial_responder]:
      for argsorder_responder in [get_trivial_responder, get_swp_responder]:
        for password_prepare in [pad_password]:
          for operation in [encrypt]:
            for cipher in [aes_ctr]:
              passwords = get_16byte_pair_passwords()
              passwords.extend(get_16byte_pair_password_repeats())
              for password in passwords:
                attempts.append([password, password_prepare, variant_responder(argsorder_responder(get_cipher_message_responder(operation, cipher))), frame_responder, str(frame_responder.__name__)+'(%d' % offset +')'+'/'+str(variant_responder.__name__)+'/'+str(argsorder_responder.__name__)+'/'+str(password_prepare.__name__)+'/'+str(operation.__name__)+'/'+str(cipher.__name__)+'/'+str(password)])

  start = 0
  for i in range(start, len(attempts)):
    password, password_prepare, message_responder, frame_responder, name = attempts[i]
    log("%d of %d" %(i, len(attempts)))
    try_frameB_response(password, password_prepare, message_responder, frame_responder, name=name)
    i = i + 1
  return

def try_frameB_moreoffsets_letencrypt_ecb_md5():
  attempts = list()

  offsets = list(range(76, 512-160-128+1, 4))
  for candidate in [203]:
    offsets.remove(candidate-127)
    offsets.remove(candidate-127+8)
    offsets.remove(candidate-7)

  for offset in offsets:
    frame_responder = get_msb_offet_and_auth_responder(offset)
    for variant_responder in [get_rev_responder, get_trivial_responder]:
      for argsorder_responder in [get_trivial_responder, get_swp_responder]:
        for password_prepare in [md5_password]:
          for operation in [encrypt]:
            for cipher in [aes_ecb]:
              passwords = get_16byte_pair_passwords()
              passwords.extend(get_16byte_pair_password_repeats())
              for password in passwords:
                attempts.append([password, password_prepare, variant_responder(argsorder_responder(get_cipher_message_responder(operation, cipher))), frame_responder, str(frame_responder.__name__)+'(%d' % offset +')'+'/'+str(variant_responder.__name__)+'/'+str(argsorder_responder.__name__)+'/'+str(password_prepare.__name__)+'/'+str(operation.__name__)+'/'+str(cipher.__name__)+'/'+str(password)])

  start = 3119
  for i in range(start, len(attempts)):
    password, password_prepare, message_responder, frame_responder, name = attempts[i]
    log("%d of %d" %(i, len(attempts)))
    try_frameB_response(password, password_prepare, message_responder, frame_responder, name=name)
    i = i + 1
  return

#explore_after_instigate()
#walk_all_response_offset()
#trigger_challenge_algorithm()
#sustain_the_challenge()

#try_suggested_challenges()
#try_jb_challenges()
#try_aes_challenges()

#try_just128bit_experiment()
#try_aes_frameB_challenges()
#continue_aes_frameB_challenges()
#continue_swapped_aes_frameB_challenges()
#try_all_aes_frameB_challenges()
#try_frameB_quadD_guess_challenges()
#try_frameB_quadD_nosd_challenges()
#try_aes_frameB_pairs_challenges_bestguess()
#try_aes_frameB_pairs_challenges_therest()
#try_aes_frameB_pairs_challenges_justdoitallagain()
#try_aes_frameB_pairs_challenges_trymorebitswapsandcmac()
#try_aes_frameB_pairs_challenges_tryrepeatingchallenge()

#explore_frames_shiftdepth()
#explore_frameB_bits()
#guess_frameB_auth_bit()
#explore_frameB_stuckbits()
#explore_auth_failed()

#explore_repeat_frameA_nochallenge()
#explore_repeat_frameB_auth_failed()

#try_startrekstarwars_anomaly()
#try_frameB_quadA_againagain()
#try_frameB_offsets_bestguesses()
#try_frameB_offsets_therest()
#try_frameB_offsets_dontforget196()
#try_frameB_offsets_theotherway_bestguess()
#try_frameB_offsets_theotherway_remainder()

#try_frameB_maybeflag()
#try_repeat_mystery_sequence()

#try_frameB_offsets_theotherotherway_notdecryptnow()
#try_frameB_offsets_theotherotherway_notdecryptnow_therest()
#try_frameB_offsets_theotherotherway_notdecryptnow_lolwut()
#try_frameB_forgottenoffsets_dumbencrypt()

#try_frameB_offsets_letencrypt_ctr()
#try_frameB_moreoffsets_letencrypt_ctr()
try_frameB_moreoffsets_letencrypt_ecb_md5()

print_any_serial()
ser.close()
bitbang.close()

