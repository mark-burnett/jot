import pkg_resources
import re


__all__ = ['get_cipher', 'get_signer', 'deserialize']


_REGISTERED_CIPHERS = {}
for ep in pkg_resources.iter_entry_points('jot_ciphers'):
    _REGISTERED_CIPHERS[re.compile(ep.name)] = ep.load()


def get_cipher(alg, key):
    for regex, wrapper in _REGISTERED_CIPHERS.iteritems():
        if regex.match(alg):
            return wrapper(alg=alg, key=key)


_REGISTERED_SIGNERS = {}
for ep in pkg_resources.iter_entry_points('jot_signers'):
    _REGISTERED_SIGNERS[re.compile(ep.name)] = ep.load()


def get_signer(alg, key):
    for regex, wrapper in _REGISTERED_SIGNERS.iteritems():
        if regex.match(alg):
            return wrapper(alg=alg, key=key)
