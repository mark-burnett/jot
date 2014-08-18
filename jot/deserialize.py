from . import codec
from . import exceptions
from . import jwe
from . import jws
from . import token
from . import jose
import json
import re


__all__ = ['deserialize', 'deserialize_jwe', 'deserialize_jws']


def deserialize_jwe(serialized_object):
    match = _JWE_REGEX.search(serialized_object)
    if match is None:
        raise exceptions.InvalidSerialization()

    return _deserialize_jwe_parts(*match.groups())


def _deserialize_jwe_parts(enc_header, enc_encrypted_key,
        enc_initialization_vector, enc_ciphertext, enc_authentication_tag):
    return jwe.JWE(
        encoded_header=enc_header,
        encoded_encrypted_key=enc_encrypted_key,
        encoded_initialization_vector=enc_initialization_vector,
        encoded_ciphertext=enc_ciphertext,
        encoded_authentication_tag=enc_authentication_tag,
    )


def deserialize_jws(serialized_object):
    match = _JWS_REGEX.search(serialized_object)
    if match is None:
        raise exceptions.InvalidSerialization()

    return _deserializs_jwe_parts(*match.groups())


def _deserialize_jws_parts(enc_header, enc_payload, enc_signature=None):
    return jws.JWS(encoded_header=enc_header,
            encoded_payload=enc_payload, encoded_signature=enc_signature)


_JWE_REGEX = re.compile(r'^([\w_-]+)\.([\w_-]*)\.([\w_-]*)\.([\w_-]+)\.([\w_-]*)$')
_JWS_REGEX = re.compile(r'^([\w_-]+)\.([\w_-]+)(?:\.([\w_-]+))?$')


_REGEXES = {
    _JWS_REGEX: _deserialize_jws_parts,
    _JWE_REGEX: _deserialize_jwe_parts,
}


def deserialize(serialized_object):
    for regex, factory in _REGEXES.iteritems():
        match = regex.search(serialized_object)
        if match:
            return factory(*match.groups())

    raise exceptions.InvalidSerialization()
