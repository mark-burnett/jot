import struct


def pkcs_7_pad(msg, key_size):
    num = key_size - (len(msg) % key_size)
    return msg + num * struct.pack('B', num)
