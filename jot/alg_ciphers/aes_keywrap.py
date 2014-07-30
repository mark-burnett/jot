from .base import AlgCipher
from jot.algo import aes_keywrap
from jot import exceptions
import binascii

INITIAL_VALUE = binascii.a2b_hex('A6A6A6A6A6A6A6A6')

class AesKeywrapCipher(AlgCipher):
    def encrypt_key(self, symmetric_key):
        return aes_keywrap.wrap(self.key, symmetric_key, IV=INITIAL_VALUE)

    def decrypt_key(self, encrypted_key):
        symmetric_key, iv = aes_keywrap.unwrap(self.key, encrypted_key)
        if iv != INITIAL_VALUE:
            raise exceptions.InvalidEncryptedKey()
        return symmetric_key
