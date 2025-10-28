import hashlib


def crack_sha1_hash(hash, use_salts=False):
    with open("./top-10000-passwords.txt") as passwords:
        for password in passwords:
            pw = password.strip()
            if use_salts:
                with open("./known-salts.txt") as salts:
                    for salt in salts:
                        s = salt.strip()
                        pw_with_s_1 = pw + s
                        if compare(hash, pw_with_s_1):
                            return pw
                        pw_with_s_2 = s + pw
                        if compare(hash, pw_with_s_2):
                            return pw
            else:
                if compare(hash, pw):
                    return pw

        return "PASSWORD NOT IN DATABASE"


def compare(hash, password):
    m = hashlib.sha1()
    m.update(password.encode())
    return m.hexdigest() == hash

