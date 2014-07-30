from .base import AlgCipher
from Crypto.Cipher import PKCS1_v1_5
from jot import exceptions


class RSA1_5Cipher(AlgCipher):
    def __init__(self, *args, **kwargs):
        super(RSA1_5Cipher, self).__init__(*args, **kwargs)
        self._encrypter = PKCS1_v1_5.new(self.key)

    def encrypt_key(self, symmetric_key):
        return self._encrypter.encrypt(symmetric_key)

    def decrypt_key(self, encrypted_key):
        sentinel = object()
        result = self._encrypter.decrypt(encrypted_key, sentinel)

        if sentinel == result:
            raise exceptions.InvalidCiphertext()

        else:
            return result
