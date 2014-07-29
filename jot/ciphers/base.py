import abc


class Cipher(object):
    __metaclass__ = abc.ABCMeta

    def __init__(self, enc, key):
        self.enc = enc
        self.key = key

    @abc.abstractmethod
    def encrypt(self, data):  # pragma: no cover
        return NotImplemented

    @abc.abstractmethod
    def decrypt(self, data):  # pragma: no cover
        return NotImplemented
