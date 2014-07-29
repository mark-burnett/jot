import base64


__all__ = ['base64url_encode', 'base64url_decode']


def base64url_encode(value):
    return base64.urlsafe_b64encode(value).rstrip('=')

def base64url_decode(value):
    return base64.urlsafe_b64decode(value + '=' * (4 - (len(value) % 4)))
