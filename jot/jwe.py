from . import codec
from . import jose
from . import token
from .loaders import get_alg_cipher, get_enc_cipher
import json


__all__ = ['JWE']


def _simple_parse(data):
    return json.loads(codec.base64url_decode(data))

def _load_obj(data):
    try:
        return json.loads(data)
    except ValueError:
        return data


class JWE(jose.JOSEObjectWithHeader):
    def __init__(self,
            encoded_header=None,
            encoded_encrypted_key=None,
            encoded_initialization_vector=None,
            encoded_ciphertext=None,
            encoded_authentication_tag=None
            ):

        header = jose.JOSEHeader(_simple_parse(encoded_header))
        super(JWE, self).__init__(header=header)

        self.encoded_header = encoded_header
        self.encoded_encrypted_key = encoded_encrypted_key
        self.encoded_initialization_vector = encoded_initialization_vector
        self.encoded_ciphertext = encoded_ciphertext
        self.encoded_authentication_tag = encoded_authentication_tag

        self.encrypted_key = codec.base64url_decode(encoded_encrypted_key)
        self.initialization_vector = codec.base64url_decode(
                encoded_initialization_vector)
        self.ciphertext = codec.base64url_decode(encoded_ciphertext)
        self.authentication_tag = codec.base64url_decode(
                encoded_authentication_tag)

    def compact_serialize(self):
        return '%s.%s.%s.%s.%s' % (self.encoded_header,
                self.encoded_encrypted_key, self.encoded_initialization_vector,
                self.encoded_ciphertext, self.encoded_authentication_tag)

    def compact_serialize_without_header(self):
        return '%s.%s.%s.%s' % (
                self.encoded_encrypted_key, self.encoded_initialization_vector,
                self.encoded_ciphertext, self.encoded_authentication_tag)

    def verify_and_decrypt_with(self, key):
        alg_cipher = get_alg_cipher(alg=self.header['alg'], key=key)
        symmetric_key = alg_cipher.decrypt_key(self.encrypted_key)
        enc_cipher = get_enc_cipher(enc=self.header['enc'], key=symmetric_key,
                initialization_vector=self.initialization_vector)

        enc_cipher.verify(self.ciphertext, self.encoded_header,
                self.authentication_tag)

        payload = enc_cipher.decrypt(self.ciphertext)
        if self.header.get('typ', '').upper() == 'JWT':
            return token.Token(header=self.header,
                    claims=jose.factory(_simple_parse(payload)))

        else:
            pl_obj = jose.factory(_load_obj(payload))
            return pl_obj
