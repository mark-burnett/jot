from .codec import base64url_encode
from jot import loaders
import abc
import copy
import json


__all__ = [
    'JOSEDictionary',
    'JOSEHeader',
    'JOSEObject',
    'factory',
]


class CompactSerializable(object):
    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def compact_serialize(self):  # pragma: no cover
        return NotImplemented

    def compact_serialize_without_header(self):
        return self.compact_serialize()



class SignableMixin(CompactSerializable):
    __metaclass__ = abc.ABCMeta

    def signed_header(self, alg):
        return JOSEHeader({'alg': alg})

    def signed_payload(self):
        return self

    def sign_with(self, key, alg=None):
        header = self.signed_header(alg=alg)
        wrapper = loaders.get_signer(alg=header['alg'], key=key)

        encoded_header = header.compact_serialize()

        payload = self.signed_payload()
        encoded_payload = payload.compact_serialize_without_header()

        signature = wrapper.sign('%s.%s' % (encoded_header, encoded_payload))

        from . import jws
        return jws.JWS(encoded_header=encoded_header,
                encoded_payload=encoded_payload,
                signature=signature)


class EncryptableMixin(CompactSerializable):
    def encrypted_header(self, alg, enc):
        return {'alg': alg, 'enc': enc}

    def encrypted_payload(self):
        return self.compact_serialize()

    def encrypt_with(self, key, alg=None, enc=None):
        alg = self.get_encryption_alg(alg)
        enc = self.get_encryption_enc(enc)

        alg_cipher = loaders.get_alg_cipher(alg=alg, key=key)
        enc_cipher = loaders.get_enc_cipher(enc=enc)

        header = self.encrypted_header(alg=alg, enc=enc)
        payload = self.encrypted_payload()

        encoded_header = header.compact_serialize()

        symmetric_key, initialization_vector, ciphertext, authentication_tag =\
                enc_cipher.encrypt(encoded_header, payload)

        encrypted_key = alg_cipher.encrypt_key(symmetric_key)

        from . import jwe
        return jwe.JWE(header=header, encrypted_key=encrypted_key,
                initialization_vector=initialization_vector,
                ciphertext=ciphertext, authentication_tag=authentication_tag)



class JOSEObject(EncryptableMixin, SignableMixin): pass


class JOSEDictionary(dict, JOSEObject):
    def __init__(self, *args, **kwargs):
        dict.__init__(self, *args, **kwargs)
        JOSEObject.__init__(self)

    def compact_serialize(self):
        return base64url_encode(json.dumps(self, separators=(',',':'),
            sort_keys=True))


class JOSEHeader(JOSEDictionary):
    def set_alg(self, alg):
        self.validate_alg(alg)
        self['alg'] = alg

    def validate_alg(self, alg):
        if 'alg' in self:
            if alg and alg != self['alg']:
                raise exceptions.InvalidAlg(
                        'Specified alg (%s) does not match the exising value '
                        'in the header (%s).' % (alg, self.header['alg']))


class JOSEObjectWithHeader(JOSEObject):
    def __init__(self, header, *args, **kwargs):
        super(JOSEObjectWithHeader, self).__init__(*args, **kwargs)
        self.header = self._validate_header(header)

    def signed_header(self, alg):
        header = copy.copy(self.header)
        header.set_alg(alg)
        return header

    @abc.abstractmethod
    def compact_serialize_without_header(self):
        return NotImplemented

    def encrypted_header(self, alg, enc):
        pass

    def _validate_header(self, header):
        if header is None:
            return JOSEHeader()

        elif isinstance(header, JOSEHeader):
            return header

        elif isinstance(header, dict):
            return JOSEHeader(header)

        else:
            raise TypeError('"header" must be a JOSEHeader')


class JOSEOctetStream(JOSEObject, bytes):
    def __init__(self, *args, **kwargs):
        bytes.__init__(self, *args, **kwargs)
        JOSEObject.__init__(self)

    def compact_serialize(self):
        return base64url_encode(self)


class JOSEString(JOSEObject, str):
    def __init__(self, *args, **kwargs):
        str.__init__(self, *args, **kwargs)
        JOSEObject.__init__(self)

    def compact_serialize(self):
        return base64url_encode(self)


class JOSEUnicode(JOSEObject, unicode):
    def __init__(self, *args, **kwargs):
        unicode.__init__(self, *args, **kwargs)
        JOSEObject.__init__(self)

    def compact_serialize(self):
        return base64url_encode(self)



def factory(data):
    if isinstance(data, JOSEObject):
        return data

    elif isinstance(data, dict):
        return JOSEDictionary(data)

    elif isinstance(data, unicode):
        return JOSEUnicode(data)

    elif isinstance(data, str):
        return JOSEString(data)

    elif isinstance(data, bytes):
        return JOSEOctetStream(data)

    else:
        raise TypeError('Data not convertible to a JOSEObject.')
