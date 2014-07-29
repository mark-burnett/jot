from . import codec
from . import jose
import json
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


def deserialize(serialized_jose_object):
    header, rest = extract_header(serialized_jose_object)

    deserializer = lookup_deserializer(header)
    return deserializer(header, rest)


_EXTRACT_HEADER_REGEX = re.compile(r'^(?P<header>[\w-]+)\.(?P<rest>[\w\.-]+)')
def extract_header(serialized_jose_object):
    result = _EXTRACT_HEADER_REGEX.match(serialized_jose_object)
    header_part = result.group('header')

    return (jose.JOSEHeader(json.loads(codec.base64url_decode(header_part))),
            result.group('rest'))


_DESERIALIZERS = {}
for ep in pkg_resources.iter_entry_points('jot_deserializers'):
    _DESERIALIZERS[ep.name] = ep.load()


def lookup_deserializer(header):
    if 'typ' in header:
        return _DESERIALIZERS[header['typ'].upper()]
