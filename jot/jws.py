from . import codec
from . import exceptions
from . import jose
from . import token
from .loaders import get_signer
import json


__all__ = ['JWS']


def _simple_parse(data):
    return json.loads(codec.base64url_decode(data))


class JWS(jose.JOSEObjectWithHeader):
    def __init__(self, encoded_payload=None, encoded_header=None,
            encoded_signature=None, signature=None):
        self.encoded_header = encoded_header
        self.encoded_payload = encoded_payload

        if encoded_signature:
            self.encoded_signature = encoded_signature
            self.signature = codec.base64url_decode(encoded_signature)

        elif signature:
            self.signature = signature
            self.encoded_signature = codec.base64url_encode(signature)

        else:
            self.encoded_signature = None
            self.signature = None

        header = jose.JOSEHeader(_simple_parse(encoded_header))
        super(JWS, self).__init__(header=header)

    def compact_serialize(self):
        return '%s.%s.%s' % (
                self.encoded_header,
                self.encoded_payload,
                self.encoded_signature)

    def compact_serialize_without_header(self):
        return '%s.%s' % (
                self.encoded_payload,
                self.encoded_signature)

    @property
    def payload(self):
        pl_obj = jose.factory(_simple_parse(self.encoded_payload))
        if self.header.get('typ', '').upper() == 'JWT':
            return token.Token(header=self.header, claims=pl_obj)

        else:
            return pl_obj

    @property
    def alg(self):
        return self.header['alg']

    def verify_with(self, key):
        wrapper = get_signer(alg=self.alg, key=key)
        return wrapper.verify(self._signed_data(), self.signature)

    def verify_with_kid(self, keychain):
        kid = self.get_header('kid')
        if not kid:
            raise exceptions.NoKeyIDSpecified()

        return self.verify_with(keychain[kid])

    def _signed_data(self):
#        print self.header
#        print self.header.compact_serialize()
#        print self.encoded_header
#        print codec.base64url_decode(self.encoded_header)

#        print self.payload_object.signed_payload()
#        print self.payload_object.signed_payload().compact_serialize()
#        print self.encoded_payload
#        print codec.base64url_decode(self.encoded_payload)

        return '%s.%s' % (self.encoded_header, self.encoded_payload)
