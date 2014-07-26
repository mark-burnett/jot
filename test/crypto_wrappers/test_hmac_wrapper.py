from jot.codec import base64url_encode, base64url_decode
from jot.crypto_wrappers.hmac_wrapper import HMACWrapper
import unittest


class TestSampleJWSDataFromSpec(unittest.TestCase):
    sample_jws_data = [
        {
            'header': '{"typ":"JWT",\r\n "alg":"HS256"}',
            'encoded_header': 'eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9',
            'payload': '{"iss":"joe",\r\n "exp":1300819380,\r\n "http://example.com/is_root":true}',
            'encoded_payload': 'eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt'
                'cGxlLmNvbS9pc19yb290Ijp0cnVlfQ',
            'key': base64url_decode(
                'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75'
                'aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow'),
            'signature': 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk',
        },
    ]

    def test_encoding_header(self):
        for data in self.sample_jws_data:
            encoded_header = base64url_encode(data['header'])
            self.assertEqual(encoded_header, data['encoded_header'])

    def test_encoding_payload(self):
        for data in self.sample_jws_data:
            encoded_payload = base64url_encode(data['payload'])
            self.assertEqual(encoded_payload, data['encoded_payload'])

    def test_sign(self):
        for data in self.sample_jws_data:
            data_to_sign = '%s.%s' % (
                    data['encoded_header'], data['encoded_payload'])

            wrapper = HMACWrapper(alg='HS256', key=data['key'])
            signature = wrapper.sign(data_to_sign)
            encoded_signature = base64url_encode(signature)

            self.assertEqual(encoded_signature, data['signature'])

    def test_verify(self):
        for data in self.sample_jws_data:
            data_to_sign = '%s.%s' % (
                    data['encoded_header'], data['encoded_payload'])

            wrapper = HMACWrapper(alg='HS256', key=data['key'])
            signature = base64url_decode(data['signature'])
            self.assertTrue(wrapper.verify(data_to_sign, signature))
