from jot import token
from jot.codec import base64url_decode
import json


def deserialize_jwt(header, rest):
    parts = rest.split('.')

    if len(parts) > 2:
        raise RuntimeError('Invalid JWT.  Too many components')

    payload = json.loads(base64url_decode(parts[0]))
    signature = None

    if len(parts) == 2:
        signature = base64url_decode(parts[1])

    return token.Token(header=header, payload=payload, signature=signature)
