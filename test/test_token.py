from jot.codec import base64url_decode
from jot.deserialize import deserialize
from jot.token import Token
import unittest


class TestTokenRoundTrip(unittest.TestCase):
    sample_data = [
        {
            'alg': 'HS256',
            'payload': {'iss': 'joe', 'fancy': 'data'},
            'sign_key': base64url_decode(
                'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75'
                'aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow'),
            'verify_key': base64url_decode(
                'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75'
                'aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow'),
        },
    ]

    def test_round_trip(self):
        for data in self.sample_data:
            original_token = Token(payload=data['payload'], alg=data['alg'])
            original_token.sign_with(data['sign_key'])

            compact_serialization = original_token.compact_serialize()

            deserialized_token = deserialize(compact_serialization)
            self.assertIsInstance(deserialized_token, Token)

            self.assertTrue(deserialized_token.verify_with(data['verify_key']))

            self.assertEqual(deserialized_token.header, original_token.header)
            self.assertEqual(deserialized_token.payload, original_token.payload)
