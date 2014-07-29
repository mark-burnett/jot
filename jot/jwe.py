from .jose import JOSEObject


__all__ = ['JWE']


class JWE(JOSEObject):
    typ = 'JWE'

    def __init__(self, header, encrypted_key, initialization_vector,
            ciphertext, authentication_tag):
        self.header = header
        self.encrypted_key = encrypted_key
        self.initialization_vector = initialization_vector
        self.ciphertext = ciphertext
        self.authentication_tag = authentication_tag

    def compact_serialize(self):
        return '%s.%s.%s.%s.%s' % (self.header, self.encrypted_key,
                self.initialization_vector, self.ciphertext,
                self.authentication_tag)
