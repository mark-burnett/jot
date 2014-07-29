from Crypto.Cipher import AES
import struct
import hmac

def encrypt(k, p, a, iv, hash_function):
    k_size = len(k) / 2
    mac_key = k[:k_size]
    enc_key = k[k_size:]

    e = _encrypt(enc_key, iv, pad(p, len(enc_key)))
    t = sign(mac_key, a, iv, e, hash_function)

    return e, t


def pad(p, k):
    num = k - (len(p) % k)
    return p + num * struct.pack('B', num)


def _encrypt(enc_key, iv, p):
    a = AES.new(enc_key, mode=AES.MODE_CBC, IV=iv)
    return a.encrypt(p)


def sign(mac_key, a, iv, e, hash_function):
    al = struct.pack('!Q', len(a) * 8)

    msg = a + iv + e + al
    m = hmac.new(mac_key, msg=msg, digestmod=hash_function).digest()

    return m[:len(mac_key)]
