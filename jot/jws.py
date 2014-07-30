from . import codec
from . import exceptions
from . import jose
from .loaders import get_signer


__all__ = ['JWS']


class JWS(jose.JOSEObjectWithHeader):
    def __init__(self, payload=None, header=None, signature=None, alg=None,
            _enc_header=None, _enc_payload=None, _enc_signature=None):
        super(JWS, self).__init__(header=header)
        self.payload = self._validate_payload(payload)

        self._validate_and_set_alg(alg)

        self._enc_header = _enc_header
        self._enc_payload = _enc_payload
        self._enc_signature = _enc_signature

        if _enc_signature:
            signature = codec.base64url_decode(_enc_signature)

        self.signature = signature

    @property
    def encoded_header(self):
        if self._enc_header is None:
            self._enc_header = self.header.compact_serialize()
        return self._enc_header

    @property
    def encoded_payload(self):
        if self._enc_payload is None:
            self._enc_payload = self.payload.compact_serialize()
        return self._enc_payload

    @property
    def encoded_signature(self):
        if self._enc_signature is None:
            self._enc_signature = codec.base64url_encode(self.signature)
        return self._enc_signature

    def compact_serialize(self):
        # error conditions:
        # - alg is not none and there is no sig
        # - alg is none and there is a sig
        # special case for alg = none:
        return '%s.%s.%s' % (self.encoded_header, self.encoded_payload,
                self.encoded_signature)

    @property
    def alg(self):
        return self.header['alg']

    @alg.setter
    def alg(self, value):
        self.header['alg'] = value

    def sign_with(self, key):
        wrapper = get_signer(alg=self.alg, key=key)
        self.signature = wrapper.sign(self._signed_data())
        return self.signature

    def verify_with(self, key):
        wrapper = get_signer(alg=self.alg, key=key)
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
        return '%s.%s' % (self.encoded_header, self.encoded_payload)

    def _validate_payload(self, payload):
        return jose.factory(payload)

    def _validate_and_set_alg(self, alg):
        if 'alg' in self.header:
            if alg and alg != self.header['alg']:
                raise exceptions.InvalidAlg(
                        'Specified alg (%s) does not match the exising value '
                        'in the header (%s).' % (alg, self.header['alg']))

        else:
            self.header['alg'] = alg or DEFAULT_ALG
