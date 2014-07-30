class InvalidAlg(ValueError): pass
class InvalidClaim(ValueError): pass
class InvalidCiphertext(ValueError): pass
class InvalidHeader(ValueError): pass
class InvalidSerialization(ValueError): pass
class InvalidSignature(Exception): pass
class InvalidUUIDType(ValueError): pass
class NoIssuerSpecified(ValueError): pass
class TokenExpired(Exception): pass

class UnrecognizedAlgorithm(RuntimeError):
    def __init__(self, algorithm_name, *args, **kwargs):
        super(UnrecognizedAlgorithm, self).__init__(
            "The algorithm named (%s) is not known to the jot library" %
            algorithm_name, *args, **kwargs)
class UnrecognizedAlg(UnrecognizedAlgorithm): pass
class UnrecognizedEnc(UnrecognizedAlgorithm): pass
