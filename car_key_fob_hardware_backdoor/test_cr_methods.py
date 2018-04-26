from cr_methods import *

import unittest

key_sequence          = bitstring.BitString(hex='2b7e151628aed2a6abf7158809cf4f3c')
#                                                00101011 01111110 00010101 00010110 00101000 10101110 11010010 10100110 10101011 11110111 00010101 10001000 00001001 11001111 01001111 00111100
key_sequence_rev      = bitstring.BitString(bin='00111100 11110010 11110011 10010000 00010001 10101000 11101111 11010101 01100101 01001011 01110101 00010100 01101000 10101000 01111110 11010100')
key_sequence_brev     = bitstring.BitString(bin='11010100 01111110 10101000 01101000 00010100 01110101 01001011 01100101 11010101 11101111 10101000 00010001 10010000 11110011 11110010 00111100')
key_sequence_rev_brev = bitstring.BitString(bin='00111100 01001111 11001111 00001001 10001000 00010101 11110111 10101011 10100110 11010010 10101110 00101000 00010110 00010101 01111110 00101011')

plain_sequence          = bitstring.BitString(hex='6bc1bee22e409f96e93d7e117393172a')
#                                                  01101011 11000001 10111110 11100010 00101110 01000000 10011111 10010110 11101001 00111101 01111110 00010001 01110011 10010011 00010111 00101010
plain_sequence_rev      = bitstring.BitString(bin='01010100 11101000 11001001 11001110 10001000 01111110 10111100 10010111 01101001 11111001 00000010 01110100 01000111 01111101 10000011 11010110')
plain_sequence_brev     = bitstring.BitString(bin='11010110 10000011 01111101 01000111 01110100 00000010 11111001 01101001 10010111 10111100 01111110 10001000 11001110 11001001 11101000 01010100')
plain_sequence_rev_brev = bitstring.BitString(bin='00101010 00010111 10010011 01110011 00010001 01111110 00111101 11101001 10010110 10011111 01000000 00101110 11100010 10111110 11000001 01101011')

cipher_sequence          = bitstring.BitString(hex='3ad77bb40d7a3660a89ecaf32466ef97')
#                                                   00111010 11010111 01111011 10110100 00001101 01111010 00110110 01100000 10101000 10011110 11001010 11110011 00100100 01100110 11101111 10010111
cipher_sequence_rev      = bitstring.BitString(bin='11101001 11110111 01100110 00100100 11001111 01010011 01111001 00010101 00000110 01101100 01011110 10110000 00101101 11011110 11101011 01011100')
cipher_sequence_brev     = bitstring.BitString(bin='01011100 11101011 11011110 00101101 10110000 01011110 01101100 00000110 00010101 01111001 01010011 11001111 00100100 01100110 11110111 11101001')
cipher_sequence_rev_brev = bitstring.BitString(bin='10010111 11101111 01100110 00100100 11110011 11001010 10011110 10101000 01100000 00110110 01111010 00001101 10110100 01111011 11010111 00111010')

class TestAesAndSwappingAndReversing(unittest.TestCase):
  def test_pkcs(self):
    expected= bitstring.BitString(b'hi\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e')
    password_sequence = bitstring.BitString(b'hi')

    self.assertEqual(pkcs(password_sequence), expected)

  def test_aes_encrypt_with_pass(self):
    #[0](deskl2373:~)> ruby -e 'print "a"*16' | openssl aes-128-ecb -nopad -nosalt -k 'password' | xxd
    #00000000: 0add 4657 3dd3 c5be aa9b 162d 4c7c 135c  ..FW=......-L|.\
    this_key_sequence    = ssl_password(bitstring.BitString(b'password'))
    this_plain_sequence  = bitstring.BitString(hex='61'*16)
    this_cipher_sequence = bitstring.BitString(hex='0add 4657 3dd3 c5be aa9b 162d 4c7c 135c')

    actual = get_cipher_message_responder(encrypt, aes_ecb)(this_key_sequence, this_plain_sequence)
    self.assertEqual(actual, this_cipher_sequence)

  def test_aes_encrypt_with_pass_and_trivial(self):
    this_key_sequence    = ssl_password(bitstring.BitString(b'password'))
    this_plain_sequence  = bitstring.BitString(hex='61'*16)
    this_cipher_sequence = bitstring.BitString(hex='0add 4657 3dd3 c5be aa9b 162d 4c7c 135c')

    actual = get_trivial_responder(get_cipher_message_responder(encrypt, aes_ecb))(this_key_sequence, this_plain_sequence)
    self.assertEqual(actual, this_cipher_sequence)

  def test_aes_encrypt_with_pass_and_argswap(self):
    this_key_sequence    = ssl_password(bitstring.BitString(b'password'))
    this_plain_sequence  = bitstring.BitString(hex='61'*16)
    this_cipher_sequence = bitstring.BitString(hex='0add 4657 3dd3 c5be aa9b 162d 4c7c 135c')

    actual = get_swp_responder(get_cipher_message_responder(encrypt, aes_ecb))(this_plain_sequence, this_key_sequence)
    self.assertEqual(actual, this_cipher_sequence)

  def test_aes_encrypt(self):
    actual = get_cipher_message_responder(encrypt, aes_ecb)(key_sequence, plain_sequence)
    self.assertEqual(actual, cipher_sequence)

  def test_aes_decrypt(self):
    actual = get_cipher_message_responder(decrypt, aes_ecb)(key_sequence, cipher_sequence)
    self.assertEqual(actual, plain_sequence)

  def test_ssl_password(self):
    actual = ssl_password(bitstring.BitString(b'password'))
    self.assertEqual(actual, bitstring.BitString(hex='5E884898DA28047151D0E56F8DC62927'))

  def test_rev(self):
    def passthrough_responder(password_sequence, challenge_sequence):
      return challenge_sequence

    actual = get_rev_responder(passthrough_responder)(key_sequence, plain_sequence_rev)
    self.assertEqual(actual, plain_sequence_rev)

  def test_aes_encrypt_rev(self):
    actual = get_rev_responder(get_cipher_message_responder(encrypt, aes_ecb))(key_sequence, plain_sequence_rev)
    self.assertEqual(actual, cipher_sequence_rev)

  def test_aes_decrypt_rev(self):
    actual = get_rev_responder(get_cipher_message_responder(decrypt, aes_ecb))(key_sequence, cipher_sequence_rev)
    self.assertEqual(actual, plain_sequence_rev)

  def test_brev(self):
    def passthrough_responder(password_sequence, challenge_sequence):
      return challenge_sequence

    actual = get_bitswapped_responder(passthrough_responder)(key_sequence, plain_sequence_brev)
    self.assertEqual(actual, plain_sequence_brev)

  def test_aes_encrypt_brev(self):
    actual = get_bitswapped_responder(get_cipher_message_responder(encrypt, aes_ecb))(key_sequence, plain_sequence_brev)
    self.assertEqual(actual, cipher_sequence_brev)

  def test_aes_decrypt_brev(self):
    actual = get_bitswapped_responder(get_cipher_message_responder(decrypt, aes_ecb))(key_sequence, cipher_sequence_brev)
    self.assertEqual(actual, plain_sequence_brev)

  def test_rev_brev(self):
    def passthrough_responder(password_sequence, challenge_sequence):
      return challenge_sequence

    actual = get_rev_bitswapped_responder(passthrough_responder)(key_sequence, plain_sequence_rev_brev)
    self.assertEqual(actual, plain_sequence_rev_brev)

  def test_aes_encrypt_rev_brev(self):
    actual = get_rev_bitswapped_responder(get_cipher_message_responder(encrypt, aes_ecb))(key_sequence, plain_sequence_rev_brev)
    self.assertEqual(actual, cipher_sequence_rev_brev)

  def test_aes_decrypt_rev_brev(self):
    actual = get_rev_bitswapped_responder(get_cipher_message_responder(decrypt, aes_ecb))(key_sequence, cipher_sequence_rev_brev)
    self.assertEqual(actual, plain_sequence_rev_brev)

  def test_aes_decrypt_wswp(self):
    actual = get_wordbitswapped_responder(get_cipher_message_responder(encrypt, aes_ecb))(key_sequence, plain_sequence) #TODO actual test vectors

  def test_aes_decrypt_wrev(self):
    actual = get_rev_wordbitswapped_responder(get_cipher_message_responder(encrypt, aes_ecb))(key_sequence, plain_sequence) #TODO actual test vectors

  def test_aes_decrypt_lswp(self):
    actual = get_longbitswapped_responder(get_cipher_message_responder(encrypt, aes_ecb))(key_sequence, plain_sequence) #TODO actual test vectors

  def test_aes_decrypt_lrev(self):
    actual = get_rev_longbitswapped_responder(get_cipher_message_responder(encrypt, aes_ecb))(key_sequence, plain_sequence) #TODO actual test vectors

  def test_aes_cmac(self):
    this_key_sequence    = bitstring.BitString(hex='2b7e151628aed2a6abf7158809cf4f3c')
    this_plain_sequence  = bitstring.BitString(hex='6bc1bee22e409f96e93d7e117393172a')
    this_hash_sequence = bitstring.BitString(hex='070a16b46b4d4144f79bdd9dd04a287c')

    actual = aes_cmac(this_key_sequence, this_plain_sequence)
    self.assertEqual(actual, this_hash_sequence)

if __name__ == '__main__':
  unittest.main()

