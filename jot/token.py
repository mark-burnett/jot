from . import exceptions
from .signed_object import SignedObject
import uuid


__all__ = ['Token']


class Token(SignedObject):
    def __init__(self, payload=None, header=None, signature=None,
            generate_jti=False, **kwargs):
        header = self._validate_header(header)
        header = self._validate_and_set_typ(header)

        payload = self._validate_payload(payload)
        payload = self._validate_and_set_jti(payload, generate_jti)
        # expire time
        # cty - content type
        # ...

        super(Token, self).__init__(payload, header, signature, **kwargs)

    def get_claim_from_namespace(self, namespace, name, uuid_version=5):
        return self.get_claim(_create_uuid_name(namespace, name, uuid_version))

    def get_claim(self, name):
        return self.payload.get(name)

    def _validate_and_set_jti(self, payload, generate_jti):
        if generate_jti:
            if 'jti' in payload:
                raise exceptions.InvalidClaim(
                    'Cannot specify "generate_jti" with existing "jti" claim.')

            else:
                payload['jti'] = _generate_jti()

        return payload

    def _validate_and_set_typ(self, header):
        if 'typ' in header and header['typ'].upper() != 'JWT':
            raise exceptions.InvalidHeader('"typ" parameter must be "JWT"')

        header['typ'] = 'JWT'

        return header


def _generate_jti():
    return uuid.uuid4().hex


_UUID_VERSIONS = {
    3: uuid.uuid3,
    5: uuid.uuid5,
}
def _create_uuid_name(namespace, name, uuid_version):
    name_creator = _UUID_VERSIONS.get(uuid_version)
    if name_creator is None:
        raise exceptions.InvalidUUIDType(
                'Invalid uuid_version specified (%s).  Valid values: %s'
                % (uuid_version, _UUID_VERSIONS.keys()))
    return str(name_creator(namespace, name))
