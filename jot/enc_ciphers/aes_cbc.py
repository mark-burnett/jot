from .base import EncCipher
from jot.algo import aes_cbc_hmac_sha
import hashlib
import os
import re


_IV_BYTES = 128 / 8


class AesCbcCipher(EncCipher):
    def __init__(self, *args, **kwargs):
        self._key_bytes = None
        self._hash_function = None
        super(AesCbcCipher, self).__init__(*args, **kwargs)

    def generate_key(self):
        return os.urandom(2 * self.key_bytes)

    @property
    def key_bytes(self):
        if self._key_bytes is None:
            self._initialize()
        return self._key_bytes

    @property
    def hash_function(self):
        if self._hash_function is None:
            self._initialize()
        return self._hash_function

    def _initialize(self):
        self._key_bytes, hash_bits = _get_bits(self.enc)
        self._hash_function = getattr(hashlib, 'sha' + hash_bits)

    def generate_initialization_vector(self):
        return os.urandom(_IV_BYTES)

    def encrypt(self, header, payload):
        ciphertext, authentication_tag = aes_cbc_hmac_sha.encrypt(k=self.key,
                p=payload, a=header, iv=self.initialization_vector,
                hash_function=self.hash_function)

        return (self.key, self.initialization_vector, ciphertext,
                authentication_tag)

    def decrypt(self, ciphertext):
        return aes_cbc_hmac_sha.decrypt(k=self.key,
                e=ciphertext, iv=self.initialization_vector)

    def verify(self, ciphertext, header, authentication_tag):
        return aes_cbc_hmac_sha.verify(k=self.key,
                e=ciphertext, a=header, t=authentication_tag,
                iv=self.initialization_vector,
                hash_function=self.hash_function)


_BITS_REGEX = re.compile(r'^A(\d+)CBC-HS(\d+)$')
def _get_bits(enc):
    match = _BITS_REGEX.search(enc)
    bit_strings = match.groups()
    return int(bit_strings[0])/8, bit_strings[1]
