from jot.crypto_base import CryptoBase
import hashlib
import hmac
import re


__all__ = ['HMACWrapper']


class HMACWrapper(CryptoBase):
    def __init__(self, *args, **kwargs):
        super(HMACWrapper, self).__init__(*args, **kwargs)
        self._hash_function = _hash_function_from_alg(self.alg)

    def sign(self, data):
        digester = hmac.HMAC(key=self.key, msg=data,
                digestmod=self._hash_function)
        return digester.digest()

    def verify(self, data, signature):
        return self.sign(data) == signature


_BITS_REGEX = re.compile(r'^HS(?P<bits>\d+)$')
def _hash_function_from_alg(alg):
    re_result = _BITS_REGEX.search(alg)
    bits_str = re_result.group('bits')

    return getattr(hashlib, 'sha' + bits_str)
