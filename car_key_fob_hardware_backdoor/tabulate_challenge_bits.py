import bitstring
import sys

from password_candidates import *
from cr_methods import *

passwords = list()
passwords.extend(get_16byte_pair_passwords())
passwords.extend(get_16byte_pair_password_repeats())

challenges = list()
with open('100challenges.txt') as f:
    for line in f:
        challenges.append(line)

COUNT = 100

def check_message_responder(password_prepare, message_responder, name):
    print(name)
    for password in passwords:
        password_sequence = bitstring.BitString(password)

        tally = [0] * 128
        for challenge in challenges:
            challenge_sequence = bitstring.BitString(hex=challenge)

            plaintext_sequence = message_responder(password_prepare(password_sequence), challenge_sequence)
            for bit in range(0, 128):
                if plaintext_sequence[bit]:
                    tally[bit] = tally[bit] + 1

        found = False
        for t in tally:
            if t <= 2 or t >= COUNT-2:
                found = True
        if found:
            print("%s: %s" % (password, ' '.join(["%02x" % i for i in tally])))

    print()
    return

for variant_responder in [get_rev_responder, get_trivial_responder, get_bitswapped_responder, get_rev_bitswapped_responder, get_wordbitswapped_responder, get_rev_wordbitswapped_responder, get_longbitswapped_responder, get_rev_longbitswapped_responder]:
    for argsorder_responder in [get_trivial_responder, get_swp_responder]:
        for operation in [encrypt]:
            for cipher in [aes_ecb]:
                for password_prepare in [pad_password, ssl_password, md5_password]:
                    check_message_responder(password_prepare, variant_responder(argsorder_responder(get_cipher_message_responder(operation, cipher))), str(variant_responder.__name__)+'/'+str(argsorder_responder.__name__)+'/'+str(operation.__name__)+'/'+str(cipher.__name__)+'/'+str(password_prepare.__name__))
