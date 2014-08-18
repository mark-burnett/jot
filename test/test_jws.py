from jot.codec import base64url_decode
from jot import deserialize
from jot.jws import JWS
from jot.token import Token
import unittest


class TestSampleData(unittest.TestCase):
    sample_data = [
        {
            'header': {'typ': 'JWT', 'alg': 'HS256'},
            'sign_alg': 'HS256',
            'claims': {'iss': 'joe', 'exp': 1300819380,
                'http://example.com/is_root': True},
            'sign_key': base64url_decode(
                'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75'
                'aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow'),
            'verify_key': base64url_decode(
                'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75'
                'aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow'),
            'signature': base64url_decode(
                'tu77b1J0ZCHMDd3tWZm36iolxZtBRaArSrtayOBDO34'),
            'encoded_header': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9',
            'encoded_payload':
                'eyJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ij'
                    'p0cnVlLCJpc3MiOiJqb2UifQ',
            'encoded_signature': 'tu77b1J0ZCHMDd3tWZm36iolxZtBRaArSrtayOBDO34',
            'compact_serialization':
                'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'
                '.'
                'eyJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ij'
                    'p0cnVlLCJpc3MiOiJqb2UifQ'
                '.'
                'tu77b1J0ZCHMDd3tWZm36iolxZtBRaArSrtayOBDO34',
        },
    ]

    def test_sign_with(self):
        for data in self.sample_data:
            t = Token(claims=data['claims'])
            jws = t.sign_with(data['sign_key'], alg=data['sign_alg'])
            self.assertEqual(jws.signature, data['signature'])

    def test_compact_serialize(self):
        for data in self.sample_data:
            jws = JWS(encoded_header=data['encoded_header'],
                    encoded_payload=data['encoded_payload'],
                    encoded_signature=data['encoded_signature'])
            self.assertEqual(jws.compact_serialize(), data['compact_serialization'])

    def test_verify_with(self):
        for data in self.sample_data:
            jws = JWS(encoded_header=data['encoded_header'],
                    encoded_payload=data['encoded_payload'],
                    encoded_signature=data['encoded_signature'])
            self.assertTrue(jws.verify_with(data['verify_key']))


class VerifyInterop(unittest.TestCase):
    sample_data = [
        {
            'compact_serialization':
                'eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9'
                '.'
                'eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leG'
                    'FtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ'
                '.'
                'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk',
            'header': {'alg': 'HS256', 'typ': 'JWT'},
            'claims': {'iss': 'joe', 'exp': 1300819380,
                'http://example.com/is_root': True},
            'verify_key': base64url_decode(
                'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75'
                'aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow'),
        },
    ]

    def test_verify_interop(self):
        for data in self.sample_data:
            jws = deserialize(data['compact_serialization'])
            self.assertEqual(jws.header, data['header'])
            self.assertTrue(jws.verify_with(data['verify_key']))
            t = jws.payload
            self.assertEqual(t.claims, data['claims'])
