import sys

from cr_methods import *
from password_candidates import *

challenges = [
'f8a24ea453581ac19525a865085feae5',
'ed74d47f94f768c53a23e1a8c4cc031b',
'f813c1771a789cf13abb232d36ad8544'
]

sd_alone = bitstring.BitString(hex='00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000000000000000')
sd_count = bitstring.BitString(hex='00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000')

blank = bitstring.BitString(bin='0'*128)

if sd_alone[-128:] & (sd_alone | sd_count)[-128:] == blank:
  print("FAIL")
  sys.exit(1)

for challenge in challenges:
  print(challenge)
  for argsorder_responder in [get_trivial_responder, get_swp_responder]:
    for password_prepare in [pad_password, ssl_password, md5_password]:
      for variant_responder in [get_rev_responder, get_bitswapped_responder, get_rev_bitswapped_responder, get_trivial_responder]:
        for operation in [decrypt, encrypt]:
          for cipher in [aes_ecb]:
            possible_passwords = list()
            name=str(argsorder_responder.__name__)+str(password_prepare.__name__)+str(variant_responder.__name__)+str(operation.__name__)+str(cipher.__name__)

            for password in passwords:

              challenge_sequence = bitstring.BitString(hex=challenge)
              password_sequence = password_prepare(bitstring.BitString(password))

              response_sequence = variant_responder(argsorder_responder(get_cipher_message_responder(operation, cipher)))(password_sequence, challenge_sequence)
              if response_sequence & (sd_alone | sd_count)[-128:] == blank:
                possible_passwords.append(password)

            print("%80s : %02d %s" % (name, len(possible_passwords), possible_passwords))
  print()
