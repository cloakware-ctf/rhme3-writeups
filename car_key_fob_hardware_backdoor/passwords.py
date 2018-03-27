passwords = [
b'princess',
b'fob',
b'qwerty',
b'secr3t',
b'admin',
b'backdoor',
b'user',
b'password',
b'letmein',
b'passwd',
b'123456',
b'administrator',
b'car',
b'zxcvbn',
b'monkey',
b'hottie',
b'love',
b'userpass',
b'wachtwoord',
b'geheim',
b'secret',
b'manufacturer',
b'tire',
b'brake',
b'gas',
b'riscurino',
b'delft',
b'sanfransisco',
b'shanghai',
b'gears',
b'login',
b'welcome',
b'solo',
b'dragon',
b'zaq1zaq1',
b'iloveyou',
b'monkey',
b'football',
b'starwars',
b'startrek',
b'cheese',
b'pass',
b'riscure',
b'aes',
b'des'
]

from itertools import chain, permutations, combinations
def permutation_powerset(input_list):
  return chain.from_iterable(permutations(input_list, r) for r in range(depth))

def powerset(input_list, depth):
  return chain.from_iterable(combinations(input_list, r) for r in range(depth))

def generate_16byte_passwords():
  target_passwords = list()
  for combo in powerset(passwords, 9):
    if len(combo) > 0:
      password=b"".join(combo)
      if len(password) == 16:
        target_passwords.append(password)
  return target_passwords

compound_passwords=generate_16byte_passwords()
print(compound_passwords)
print(len(compound_passwords))
