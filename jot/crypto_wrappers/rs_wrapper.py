from .base import CryptoWrapperBase
import Crypto.Hash
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
import hashlib
import re


__all__ = ['RSWrapper']


class RSWrapper(CryptoWrapperBase):
    def __init__(self, *args, **kwargs):
        super(RSWrapper, self).__init__(*args, **kwargs)
        self.signer = PKCS1_v1_5.new(self.key)

    def sign(self, data):
        hash_obj = _hash_function_from_alg(self.alg).new(data)
        return self.signer.sign(hash_obj)

    def verify(self, data, signature):
        hash_obj = _hash_function_from_alg(self.alg).new(data)
        return self.signer.verify(hash_obj, signature)


_BITS_REGEX = re.compile(r'^RS(?P<bits>\d+)$')
def _hash_function_from_alg(alg):
    re_result = _BITS_REGEX.search(alg)
    bits_str = re_result.group('bits')

    return getattr(Crypto.Hash, 'SHA' + bits_str)
