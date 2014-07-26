from . import codec
from . import jose
import json
import pkg_resources
import re


__all__ = ['get_crytpo_wrapper', 'deserialize']


_REGISTERED_CRYPTO_WRAPPERS = {}
for ep in pkg_resources.iter_entry_points('jot_crypto_wrappers'):
    _REGISTERED_CRYPTO_WRAPPERS[re.compile(ep.name)] = ep.load()


def get_crytpo_wrapper(alg, key):
    for regex, wrapper in _REGISTERED_CRYPTO_WRAPPERS.iteritems():
        if regex.match(alg):
            return wrapper(alg=alg, key=key)


def deserialize(serialized_jose_object):
    header, rest = extract_header(serialized_jose_object)

    deserializer = lookup_deserializer(header)
    return deserializer(header, rest)


_EXTRACT_HEADER_REGEX = re.compile(r'^(?P<header>[\w-]+)\.(?P<rest>[\w\.-]+)')
def extract_header(serialized_jose_object):
    result = _EXTRACT_HEADER_REGEX.match(serialized_jose_object)
    header_part = result.group('header')

    return jose.JOSEHeader(json.loads(codec.base64url_decode(header_part))), result.group('rest')


_DEFAULT_DESERIALIZER = next(pkg_resources.iter_entry_points(
    'jot_default_deserializer', 'default')).load()
_DESERIALIZERS = {}
for ep in pkg_resources.iter_entry_points('jot_deserializers'):
    _DESERIALIZERS[ep.name] = ep.load()


def lookup_deserializer(header):
    if 'typ' in header:
        return _DESERIALIZERS[header['typ'].upper()]

    else:
        return _DEFAULT_DESERIALIZER(header, rest)
