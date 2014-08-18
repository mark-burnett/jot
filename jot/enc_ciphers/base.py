from jot import exceptions
import abc


class EncCipher(object):
    __metaclass__ = abc.ABCMeta

    def __init__(self, enc, key=None, initialization_vector=None):
        self.enc = enc

        if key:
            self.key = key
        else:
            self.key = self.generate_key()

        if initialization_vector:
            self.initialization_vector = initialization_vector
        else:
            self.initialization_vector = self.generate_initialization_vector()

    @abc.abstractmethod
    def generate_key(self):  # pragma: no cover
        return NotImplemented

    @abc.abstractmethod
    def generate_initialization_vector(self):  # pragma: no cover
        return NotImplemented

    @abc.abstractmethod
    def encrypt(self, header, payload):  # pragma: no cover
        return NotImplemented

    @abc.abstractmethod
    def decrypt(self, ciphertext):  # pragma: no cover
        return NotImplemented

    @abc.abstractmethod
    def verify(self, ciphertext, header,
            authentication_tag):  # pragma: no cover
        return NotImplemented
