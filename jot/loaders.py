import pkg_resources
import re
from . import exceptions


__all__ = ['get_alg_cipher', 'get_enc_cipher', 'get_signer']


_REGISTERED_ALG_CIPHERS = {}
for ep in pkg_resources.iter_entry_points('jot_alg_ciphers'):
    _REGISTERED_ALG_CIPHERS[re.compile(ep.name)] = ep.load()


def get_alg_cipher(alg, key):
    for regex, wrapper in _REGISTERED_ALG_CIPHERS.iteritems():
        if regex.match(alg):
            return wrapper(alg=alg, key=key)
    raise exceptions.UnrecognizedAlg(alg)


_REGISTERED_ENC_CIPHERS = {}
for ep in pkg_resources.iter_entry_points('jot_enc_ciphers'):
    _REGISTERED_ENC_CIPHERS[re.compile(ep.name)] = ep.load()


def get_enc_cipher(enc, key=None, initialization_vector=None):
    for regex, wrapper in _REGISTERED_ENC_CIPHERS.iteritems():
        if regex.match(enc):
            return wrapper(enc=enc, key=key,
                    initialization_vector=initialization_vector)
    raise exceptions.UnrecognizedEnc(enc)


_REGISTERED_SIGNERS = {}
for ep in pkg_resources.iter_entry_points('jot_signers'):
    _REGISTERED_SIGNERS[re.compile(ep.name)] = ep.load()


def get_signer(alg, key):
    for regex, wrapper in _REGISTERED_SIGNERS.iteritems():
        if regex.match(alg):
            return wrapper(alg=alg, key=key)
    raise exceptions.UnrecognizedAlg(alg)
