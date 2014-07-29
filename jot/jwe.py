from .jose import JOSEObject


__all__ = ['JWE']


class JWE(JOSEObject):
    def __init__(self, header, encrypted_key, initialization_vector,
            ciphertext, authentication_tag):
        self.header = header
        self.encrypted_key = encrypted_key
        self.initialization_vector = initialization_vector
        self.ciphertext = ciphertext
        self.authentication_tag = authentication_tag

    def compact_serialize(self):
        return '%s.%s.%s.%s.%s' % (self.header.compact_serialize(),
                self.encrypted_key, self.initialization_vector, self.ciphertext,
                self.authentication_tag)

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

    def decrypt_with(self, key):
        # Probably need more arguments
        pass
