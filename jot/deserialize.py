from . import codec
from . import exceptions
from . import jwe
from . import jws
from . import token
import json
import re


_JWE_REGEX = re.compile(r'^([\w_-]+)\.([\w_-]+)\.([\w_-]+)\.([\w_-]+)\.([\w_-]+)$')
_JWS_REGEX = re.compile(r'^([\w_-]+)\.([\w_-]+)(?:\.([\w_-]+))?$')


_JWE_JWS_REGEX = re.compile(r'^([\w_-]+)\.([\w_-]+)(?:\.([\w_-]+)(?:\.([\w_-]+)\.([\w_-]+))?)?$')


def deserialize_jwe(serialized_object):
    match = _JWE_REGEX.search(serialized_object)
    if match is None:
        raise exceptions.InvalidSerialization()

    return _deserialize_jwe_parts(*match.groups())


def _deserialize_jwe_parts(enc_header, enc_encrypted_key,
        enc_initialization_vector, enc_ciphertext, enc_authentication_tag):
    pass


def deserialize_jws(serialized_object):
    match = _JWS_REGEX.search(serialized_object)
    if match is None:
        raise exceptions.InvalidSerialization()

    return _deserializs_jwe_parts(*match.groups())


def _deserialize_jws_parts(enc_header, enc_payload, enc_signature=None):
    header = json.loads(codec.base64url_decode(enc_header))
    payload = json.loads(codec.base64url_decode(enc_payload))

    if enc_signature is None:
        signature = None

    else:
        signature = codec.base64url_decode(enc_signature)

    if header.get('typ'):
        cls = token.Token
    else:
        cls = jws.JWS

    return cls(header=header, payload=payload, signature=signature)


def deserialize(serialized_object):
    match = _JWE_JWS_REGEX.search(serialized_object)
    if match is None:
        raise exceptions.InvalidSerialization()

    parts = match.groups()

    if parts[-1] is None:
        return _deserialize_jws_parts(*parts[:3])

    else:
        return _deserialize_jwe_parts(*parts)
