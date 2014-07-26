import pkg_resources
import re


__all__ = ['get_crytpo_wrapper']


_REGISTERED_CRYPTO_WRAPPERS = {}
for ep in pkg_resources.iter_entry_points('jot_crypto_wrappers'):
    _REGISTERED_CRYPTO_WRAPPERS[re.compile(ep.name)] = ep.load()


def get_crytpo_wrapper(alg, key):
    for regex, wrapper in _REGISTERED_CRYPTO_WRAPPERS.iteritems():
        if regex.match(alg):
            return wrapper(alg=alg, key=key)
