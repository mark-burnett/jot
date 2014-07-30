from Crypto.Cipher import AES
import binascii
import copy
import struct


def wrap(key, plaintext, IV=binascii.a2b_hex('A6A6A6A6A6A6A6A6')):
    cipher = AES.new(key)
    A = IV
    P = chunk(plaintext, 8)
    R = [0] + copy.copy(P)
    n = len(P)

    for j in range(6):
        for i in xrange(1, n+1):
            B = cipher.encrypt(A + R[i])
            t = n*j + i
            A = struct.pack('!Q', struct.unpack('!Q', B[:8])[0] ^ t)
            R[i] = B[-8:]

    R[0] = A
    return ''.join(R)

def unwrap(key, ciphertext):
    cipher = AES.new(key)
    C = chunk(ciphertext, 8)
    A = C[0]
    R = copy.copy(C)
    n = len(C) - 1

    for j in xrange(5, -1, -1):
        for i in xrange(n, 0, -1):
            t = n*j + i
            B = cipher.decrypt(
                    struct.pack('!Q', struct.unpack('!Q', A)[0] ^ t)
                    + R[i])
            A = B[:8]
            R[i] = B[-8:]


    return ''.join(R[1:]), A


def chunk(string, size):
    num_chunks = len(string)/size
    assert len(string) == num_chunks * size

    return [string[i*size: (i+1)*size] for i in xrange(num_chunks)]
