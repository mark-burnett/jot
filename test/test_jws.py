from Crypto.PublicKey import RSA
from jot.codec import base64url_decode
from jot.loaders import deserialize
from jot.jws import JWS
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
                'tu77b1J0ZCHMDd3tWZm36iolxZtBRaArSrtayOBDO34'),
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
            so = JWS(header=data['header'], payload=data['payload'])
            self.assertEqual(so.sign_with(data['sign_key']), data['signature'])

    def test_compact_serialize(self):
        for data in self.sample_data:
            so = JWS(header=data['header'], payload=data['payload'])
            so.sign_with(data['sign_key'])
            self.assertEqual(so.compact_serialize(),
                    data['compact_serialization'])

    def test_verify_with(self):
        for data in self.sample_data:
            so = JWS(header=data['header'], payload=data['payload'],
                    signature=data['signature'])
            self.assertTrue(so.verify_with(data['verify_key']))


PRIVATE_KEY = '''-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAyM5QtdqcEALi+J/Jtv9XzQBmkN6yyhghquEWmPKIvBebpDnx
fvCDg5OwthDGr6fZ9BCpCWvKwfQOPoAkLNA+A+BZSbYwgpQrSzIKzDmqEgN/fja9
zdlsRc/d0/1+0fzIOZ0H8oOiM6lv1JhnyIBZZfi1286oM82KEVrgnynvgX1IBAZL
tKu7ZYh9TPkigPirXIvUHvWu827a0YBnzCqsK9NLEsU1cYyZEBS5I9Z3Kxq4PJsr
803qCCtz89jJPvpMVC+37IMPYnISOBG39HmdcKqsC2Blwu1O7TPoV6ajuGixg9QJ
DEqNy4AzYMJcmqFOQY8cYtEjUtOlxgsbJ1Uz8wIDAQABAoIBAFpONoviGWc19R78
tTmAEdtWv8mM7Xjna1Suz3vPLuDv+QXdLRb6URq+M61dVA0w/lq9l1duS4v4FuPS
uvIQYKNbpKv6rEw9GE9D3QlFMY/SVObM9YT6r6+hsNAiY4NKHD2Uujs9KZf0Lh+8
voez+QBb3mVQxeIuIFZ3uSa7NEPV5z3mfSJptcWqygqKhyJSC6D7uCcyhfVqlmM5
FQ4uCMi5WhYEOKl/90EAPvrPVZSnoQVt715AfSCw+tk1wzB+9HvntFlE5Kiuc0Ib
hEH7CcCTgd44JbxgsySz1RrSkAltOOhdj3SDoLtMMoF2nWgj2jMmD83sfjSU6EaP
ayrgaAECgYEAyOjmTVWoAnc8F0zvKqrfoeo2k3PrSMaiFQFGwTfkmR+38wGyiqsy
airnyLnI3w1TxevmrTmdTIKv+9d23Qk0bhqALgzC1pyOJNahL/M8LsqKVnw3WoiD
aRjza9GxZk25/c5zPKORO6y6XDR3v0DWNvQbUG0yspSYq4RnjCfE1AECgYEA/94g
SeVjEyO2QZg4TTYlJT/+v5ZjaTlqcO+udxUTjrO8MQL5FwD1mjf7k8UR8UTGa2V7
bijhKpIIUvEzE3oRq5Q3pQj9T3kWqYez9y4kwgLR9RQUrP+xbjHKbdsS+1Em+00p
EjnPgKJJcUpIaxHzKjY3GZXqNxgRXVUkNULz9/MCgYAFH2MX37I79dxTX8PNW7P+
BeHEWrVKEr55OKIcNRegC9391TI/NORBLrzgMlR703QqXLxx+EEZfU+NZU4DjsOG
dyiDhBHHtRAuwkYz2cjUDJgAYoRqy4ZGPLugKSWTzTGL1iK8DhOa6OmLhk7zUmzj
08+Kem5LfVxzKxoUycLMAQKBgQDw8ijvzX594IxZutGSDCHwsRHhMuqMhU/x6BMf
+o3/PMxETytn+TRPNNbI8bSSwhQjwF36f66CGyCRkqdpePM44wt/czavZzTrEmpr
o11kAanbozxRKTvZrDOXPczjMymFTsUVb7EyziBg+fW2NiIJpyI+CsmTdiur+2hs
a4849wKBgAh7a3lrgHZy18H67lppF63YoQnvIP6etv83t1syU1WIpHLHKrUG2Lxc
cj14qA9O1abZbXu3G0m4QLvRjWIEtXVBfqak0fZSxe1yJARDjVGm5oZyH6amXF8q
+LS3MD90D/MUQZJW6L/1ceJ9aYiLqzY769rL/Bdz9HjsLPGsDTlR
-----END RSA PRIVATE KEY-----'''

PUBLIC_KEY = '''-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyM5QtdqcEALi+J/Jtv9X
zQBmkN6yyhghquEWmPKIvBebpDnxfvCDg5OwthDGr6fZ9BCpCWvKwfQOPoAkLNA+
A+BZSbYwgpQrSzIKzDmqEgN/fja9zdlsRc/d0/1+0fzIOZ0H8oOiM6lv1JhnyIBZ
Zfi1286oM82KEVrgnynvgX1IBAZLtKu7ZYh9TPkigPirXIvUHvWu827a0YBnzCqs
K9NLEsU1cYyZEBS5I9Z3Kxq4PJsr803qCCtz89jJPvpMVC+37IMPYnISOBG39Hmd
cKqsC2Blwu1O7TPoV6ajuGixg9QJDEqNy4AzYMJcmqFOQY8cYtEjUtOlxgsbJ1Uz
8wIDAQAB
-----END PUBLIC KEY-----'''

class TestSerializeRoundTrip(unittest.TestCase):
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
        },

        {
            'header': {'typ': 'JWT', 'alg': 'RS256'},
            'payload': {'iss': 'joe', 'exp': 1300819380,
                'http://example.com/is_root': True},
            'sign_key': RSA.importKey(PRIVATE_KEY),
            'verify_key': RSA.importKey(PUBLIC_KEY),
        },

    ]

    def test_round_trip(self):
        for data in self.sample_data:
            original_so = JWS(header=data['header'],
                    payload=data['payload'])
            original_so.sign_with(data['sign_key'])

            compact_serialization = original_so.compact_serialize()

            deserialized_so = deserialize(compact_serialization)
            self.assertIsInstance(deserialized_so, JWS)

            self.assertTrue(deserialized_so.verify_with(data['verify_key']))

            self.assertEqual(deserialized_so.header, data['header'])
            self.assertEqual(deserialized_so.payload, data['payload'])
