from . import codec
from . import crypto
from . import exceptions
from . import jose


__all__ = ['SignedObject']


class SignedObject(jose.JOSEObject):
    def __init__(self, payload=None, header=None, signature=None, alg=None):
        self.header = self._validate_header(header)
        self.payload = self._validate_payload(payload)

        self.signature = signature
        self._validate_and_set_alg(alg)

    def compact_serialize(self):
        # error conditions:
        # - alg is not none and there is no sig
        # - alg is none and there is a sig
        # special case for alg = none:
        return '%s.%s.%s' % (
                self.header.compact_serialize(),
                self.payload.compact_serialize(),
                codec.base64url_encode(self.signature))

    @property
    def alg(self):
        return self.header['alg']

    @alg.setter
    def alg(self, value):
        self.header['alg'] = value

    def sign_with(self, key):
        wrapper = crypto.get_crytpo_wrapper(alg=self.alg, key=key)
        self.signature = wrapper.sign(self._signed_data())
        return self.signature

    def verify_with(self, key):
        wrapper = crypto.get_crytpo_wrapper(alg=self.alg, key=key)
        return wrapper.verify(self._signed_data(), self.signature)

    def verify_with_kid(self, keychain):
        kid = self.get_header('kid')
        if not kid:
            raise exceptions.NoKeyIDSpecified()

        return self.verify_with(keychain[kid])

    def encrypt_with(self, key):
        # returns a JWE object
        pass

    def _signed_data(self):
        return '%s.%s' % (self.header.compact_serialize(),
                self.payload.compact_serialize())

    def _validate_header(self, header):
        if header is None:
            return jose.JOSEHeader()

        elif isinstance(header, jose.JOSEHeader):
            return header

        elif isinstance(header, dict):
            return jose.JOSEHeader(header)

        else:
            raise TypeError('"header" must be a JOSEHeader')

    def _validate_payload(self, payload):
        if isinstance(payload, jose.JOSEDictionary):
            return payload

        elif isinstance(payload, dict):
            return jose.JOSEDictionary(payload)

        else:
            raise TypeError('"payload" must be a dict or JOSEDictionary')

    def _validate_and_set_alg(self, alg):
        if 'alg' in self.header:
            if alg and alg != self.header['alg']:
                raise exceptions.InvalidAlg(
                        'Specified alg (%s) does not match the exising value '
                        'in the header (%s).' % (alg, self.header['alg']))

        else:
            self.header['alg'] = alg or DEFAULT_ALG
