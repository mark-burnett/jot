from .codec import base64url_encode
from . import jose
from .loaders import get_alg_cipher, get_enc_cipher


__all__ = ['JWE']


class JWE(jose.JOSEObjectWithHeader):
    def __init__(self, header, payload=None, encrypted_key=None,
            initialization_vector=None, ciphertext=None,
            authentication_tag=None, _enc_header=None, _enc_encrypted_key=None,
            _enc_initialization_vector=None, _enc_ciphertext=None,
            _enc_authentication_tag=None):
        self.header = self._validate_header(header)

        if payload:
            self.payload = jose.factory(payload)
        else:
            self.payload = None
        self._enc_payload = None

        self.encrypted_key = encrypted_key
        self.initialization_vector = initialization_vector
        self.ciphertext = ciphertext
        self.authentication_tag = authentication_tag

        self._enc_header = _enc_header
        self._enc_encrypted_key = _enc_encrypted_key
        self._enc_initialization_vector = _enc_initialization_vector
        self._enc_ciphertext = _enc_ciphertext
        self._enc_authentication_tag = _enc_authentication_tag

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
    def encoded_encrypted_key(self):
        if self._enc_encrypted_key is None:
            self._enc_encrypted_key = base64url_encode(self.encrypted_key)
        return self._enc_encrypted_key

    @property
    def encoded_initialization_vector(self):
        if self._enc_initialization_vector is None:
            self._enc_initialization_vector = base64url_encode(
                    self.initialization_vector)
        return self._enc_initialization_vector

    @property
    def encoded_ciphertext(self):
        if self._enc_ciphertext is None:
            self._enc_ciphertext = base64url_encode(self.ciphertext)
        return self._enc_ciphertext

    @property
    def encoded_authentication_tag(self):
        if self._enc_authentication_tag is None:
            self._enc_authentication_tag = base64url_encode(
                    self.authentication_tag)
        return self._enc_authentication_tag

    def compact_serialize(self):
        return '%s.%s.%s.%s.%s' % (self.encoded_header,
                self.encoded_encrypted_key, self.encoded_initialization_vector,
                self.encoded_ciphertext, self.encoded_authentication_tag)

    @property
    def alg(self):
        return self.header['alg']

    @alg.setter
    def alg(self, value):
        self.header['alg'] = value

    @property
    def enc(self):
        return self.header['enc']

    @enc.setter
    def enc(self, value):
        self.header['enc'] = value

    def encrypt_with(self, key):
        enc_cipher = get_enc_cipher(enc=self.enc)
        alg_cipher = get_alg_cipher(alg=self.alg, key=key)
        symmetric_key, initialization_vector, ciphertext, authentication_tag =\
                enc_cipher.encrypt(self.encoded_header, self.payload)

        self.initialization_vector = initialization_vector
        self.ciphertext = ciphertext
        self.authentication_tag = authentication_tag

        self.encrypted_key = alg_cipher.encrypt_key(symmetric_key)

    def verify_and_decrypt_with(self, key):
        alg_cipher = get_alg_cipher(alg=self.alg, key=key)
        symmetric_key = alg_cipher.decrypt_key(self.encrypted_key)
        enc_cipher = get_enc_cipher(enc=self.enc, key=symmetric_key,
                initialization_vector=self.initialization_vector)

        enc_cipher.verify(self.ciphertext, self.encoded_header,
                self.authentication_tag)

        self.payload = enc_cipher.decrypt(self.ciphertext)
