class CryptoBase(object):
    def __init__(self, alg, key):
        self.alg = alg
        self.key = key

    def decrypt(self, data):  # pragma: no cover
        return NotImplemented

    def encrypt(self, data):  # pragma: no cover
        return NotImplemented

    def sign(self, data):  # pragma: no cover
        return NotImplemented

    def verify(self, data, signature):  # pragma: no cover
        return NotImplemented
