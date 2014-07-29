from .padding import pkcs_7_pad
from Crypto.Cipher import AES
import struct
import hmac


__all__ = ['decrypt', 'encrypt', 'verify']


def decrypt():
    pass


def encrypt(k, p, a, iv, hash_function):
    mac_key, enc_key = _split_key(k)
    e = _encrypt(enc_key, iv, pkcs_7_pad(p, len(enc_key)))
    t = _sign(mac_key, a, iv, e, hash_function)

    return e, t


def verify(k, e, a, iv, t, hash_function):
    mac_key, enc_key = _split_key(k)
    actual_t = _sign(mac_key, a, iv, e, hash_function)
    return t == actual_t


def _split_key(k):
    k_size = len(k) / 2
    mac_key = k[:k_size]
    enc_key = k[k_size:]
    return mac_key, enc_key


def _encrypt(enc_key, iv, p):
    a = AES.new(enc_key, mode=AES.MODE_CBC, IV=iv)
    return a.encrypt(p)


def _sign(mac_key, a, iv, e, hash_function):
    al = struct.pack('!Q', len(a) * 8)

    msg = a + iv + e + al
    m = hmac.new(mac_key, msg=msg, digestmod=hash_function).digest()

    return m[:len(mac_key)]
