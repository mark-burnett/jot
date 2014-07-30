import abc


class AlgCipher(object):
    __metaclass__ = abc.ABCMeta

    def __init__(self, alg, key):
        self.alg = alg
        self.key = key

    def encrypt_key(self, symmetric_key):  # pragma: no cover
        return NotImplemented

    def decrypt_key(self, encrypt_key):  # pragma: no cover
        return NotImplemented
