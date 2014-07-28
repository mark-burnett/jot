import abc


class Signer(object):
    __metaclass__ = abc.ABCMeta

    def __init__(self, alg, key):
        self.alg = alg
        self.key = key

    @abc.abstractmethod
    def sign(self, data):  # pragma: no cover
        return NotImplemented

    @abc.abstractmethod
    def verify(self, data, signature):  # pragma: no cover
        return NotImplemented
