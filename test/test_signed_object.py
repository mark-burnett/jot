from jot.codec import base64url_decode
from jot.loaders import deserialize
from jot.signed_object import SignedObject
import unittest


class TestSampleData(unittest.TestCase):
    sample_data = [
        {
            'header': {'typ': 'JWT', 'alg': 'HS256'},
            'payload': {'iss': 'joe', 'exp': 1300819380,
                'http://example.com/is_root': True},
            'sign_key': base64url_decode(
                'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75'
                'aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow'),
            'verify_key': base64url_decode(
                'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75'
                'aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow'),
            'signature': base64url_decode(
                'd6nMDXnJZfNNj-1o1e75s6d0six0lkLp5hSrGaz4o9A'),
            'compact_serialization':
                'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'
                '.'
                'eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLm'
                    'NvbS9pc19yb290Ijp0cnVlfQ'
                '.'
                'd6nMDXnJZfNNj-1o1e75s6d0six0lkLp5hSrGaz4o9A',
        },
    ]

    def test_sign_with(self):
        for data in self.sample_data:
            so = SignedObject(header=data['header'], payload=data['payload'])
            self.assertEqual(so.sign_with(data['sign_key']), data['signature'])

    def test_compact_serialize(self):
        for data in self.sample_data:
            so = SignedObject(header=data['header'], payload=data['payload'])
            so.sign_with(data['sign_key'])
            self.assertEqual(so.compact_serialize(),
                    data['compact_serialization'])

    def test_verify_with(self):
        for data in self.sample_data:
            so = SignedObject(header=data['header'], payload=data['payload'],
                    signature=data['signature'])
            self.assertTrue(so.verify_with(data['verify_key']))


class TestSerializeRoundTrip(unittest.TestCase):
    sample_data = [
        {
            'header': {'typ': 'JWT', 'alg': 'HS256'},
            'payload': {'iss': 'joe', 'exp': 1300819380,
                'http://example.com/is_root': True},
            'key': base64url_decode(
                'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75'
                'aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow'),
        },
    ]

    def test_round_trip(self):
        for data in self.sample_data:
            original_so = SignedObject(header=data['header'],
                    payload=data['payload'])
            original_so.sign_with(data['key'])

            compact_serialization = original_so.compact_serialize()

            deserialized_so = deserialize(compact_serialization)
            self.assertIsInstance(deserialized_so, SignedObject)

            self.assertTrue(deserialized_so.verify_with(data['key']))

            self.assertEqual(deserialized_so.header, data['header'])
            self.assertEqual(deserialized_so.payload, data['payload'])
