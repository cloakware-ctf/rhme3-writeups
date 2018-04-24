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

def get_16byte_pair_passwords():
    password_candidates = list()

    for password1 in passwords:
        for password2 in passwords:
            if password1 == password2:
                continue
            test_password = bytearray()
            test_password.extend(password1)
            test_password.extend(password2)
            if len(test_password) == 16:
                password_candidates.append(bytes(test_password))

    return password_candidates

def get_16byte_pair_password_repeats():
    password_candidates = list()

    for password1 in passwords:
        password2 = password1
        test_password = bytearray()
        test_password.extend(password1)
        test_password.extend(password2)
        if len(test_password) == 16:
            password_candidates.append(bytes(test_password))

    return password_candidates
