from . import exceptions
from . import jose
import datetime
import time
import uuid


__all__ = ['Token']


class Token(jose.JOSEObjectWithHeader):
    def __init__(self, claims=None, header=None, generate_jti=False, **kwargs):
        super(Token, self).__init__(header=header)
        claims = self._validate_claims(claims)
        claims = self._validate_and_set_jti(claims, generate_jti)

        self.claims = claims

    def compact_serialize(self):
        return '%s.%s' % (self.header.compact_serialize(),
                self.claims.compact_serialize())

    def compact_serialize_without_header(self):
        return self.claims.compact_serialize()

    def signed_payload(self):
        return self.claims

    def encrypted_payload(self):
        return self.compact_serialize_without_header()

    def signed_header(self, alg):
        header = super(Token, self).signed_header(alg)
        header['typ'] = 'JWT'
        return header

    def encrypted_header(self, alg, enc):
        header = super(Token, self).encrypted_header(alg, enc)
        header['typ'] = 'JWT'
        return header

    @property
    def is_valid(self):
        now = int(time.mktime(datetime.datetime.utcnow().timetuple()))
        if 'exp' in self.claims:
            exp = int(self.claims['exp'])
            if now > exp:
                return False

        if 'iat' in self.claims:
            if now < int(self.claims['iat']):
                return False

        return True


    def _validate_claims(self, claims):
        if isinstance(claims, jose.JOSEDictionary):
            return claims

        elif isinstance(claims, dict):
            return jose.JOSEDictionary(claims)

        elif claims is None:
            return jose.JOSEDictionary()

        else:
            raise TypeError('"claims" must be a dict or JOSEDictionary')

    def _validate_and_set_jti(self, claims, generate_jti):
        if generate_jti:
            if 'jti' in claims:
                raise exceptions.InvalidClaim(
                    'Cannot specify "generate_jti" with existing "jti" claim.')

            else:
                claims['jti'] = _generate_jti()

        return claims


    def get_claim_from_namespace(self, namespace, name, uuid_version=5):
        return self.get_claim(_create_uuid_name(namespace, name, uuid_version))

    def get_claim(self, name):
        return self.claims.get(name)

    def set_claim_in_namespace(self, namespace, name, value, uuid_version=5):
        self.claims[_create_uuid_name(namespace, name, uuid_version)] = value

    def set_claim(self, name, value):
        self.claims[name] = value

    def has_audience(self, expected_aud):
        return (expected_aud == self.claims.get('aud', object())
                or expected_aud in self.claims.get('aud', []))


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
