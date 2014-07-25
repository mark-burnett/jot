from jot.codec import base64url_encode, base64url_decode
import unittest


class TestSampleDataFromSpecs(unittest.TestCase):
    sample_data = [
        ('{"typ":"JWT",\r\n "alg":"HS256"}',
            'eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9'),
        ('{"iss":"joe",\r\n "exp":1300819380,\r\n "http://example.com/is_root":true}',
             'eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ'),
        ('{"alg":"none"}',
            'eyJhbGciOiJub25lIn0'),
    ]

    def test_encoder(self):
        for unencoded, encoded in self.sample_data:
            self.assertEqual(base64url_encode(unencoded), encoded,
                'Failed to encode data for: %r' % unencoded)

    def test_decoder(self):
        for unencoded, encoded in self.sample_data:
            self.assertEqual(base64url_decode(encoded), unencoded,
                'Failed to decode data for: %r' % encoded)


class RountTripCodecTest(unittest.TestCase):
    sample_data = [
        '{"something": "else"}',
        'this9codec\nshould^be!able.to,encode?arbitrary strings',
    ]

    def test_round_trip(self):
        for data in self.sample_data:
            self.assertEqual(base64url_decode(base64url_encode(data)), data,
                    'Failed to round trip data: %r' % data)
