from Crypto.PublicKey import RSA
from jot.codec import base64url_decode
import unittest


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


class TestEncryptionRoundTrip(unittest.TestCase):
    sample_data = [
        {
            'header': {'alg': 'RSA1_5', 'enc': 'A128CBC-HS256'},
            'payload': 'this is a sample sequence to encrypt',
            'encrypt_key': RSA.importKey(PUBLIC_KEY),
            'decrypt_key': RSA.importKey(PRIVATE_KEY),
        },

    ]

    def test_round_trip(self):
        pass

    def test_ciphertext_different_each_time(self):
        pass


class TestEncryptionInterop(unittest.TestCase):
    sample_data = [
        {
            'decrypt_key': RSA.construct((base64url_decode(
                    'sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bOdgWp4Dy1Wl'
                    'UzewbgBHod5pcM9H95GQRV3JDXboIRROSBigeC5yjU1hGzHHyXss8UDpre'
                    'cbAYxknTcQkhslANGRUZmdTOQ5qTRsLAt6BTYuyvVRdhS8exSZEy_c4gs_'
                    '7svlJJQ4H9_NxsiIoLwAEk7-Q3UXERGYw_75IDrGA84-lA_-Ct4eTlXHBI'
                    'Y2EaV7t7LjJaynVJCpkv4LKjTTAumiGUIuQhrNhZLuF_RJLqHpM2kgWFLU'
                    '7-VTdL1VbC2tejvcI2BlMkEpk1BzBZI0KQB0GaDWFLN-aEAw3vRw'
                ),
                base64url_decode('AQAB'),
            )),
            'expected_header': {'alg': 'RSA1_5', 'enc': 'A128CBC-HS256'},
            'expected_payload': 'Live long and prosper.',
            'compact_serialization':
                'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.'
                '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ.'
                'AxY8DCtDaGlsbGljb3RoZQ.'
                'KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY.'
                'U0m_YmjN04DJvceFICbCVQ',
        },
    ]

    def test_header(self):
        for data in self.sample_data:
            jwe = deserialize(data['compact_serialization'])
            self.assertEqual(jwe.header, data['header'])

    def test_verify(self):
        for data in self.sample_data:
            jwe = deserialize(data['compact_serialization'])
            self.assertTrue(jwe.verify_with(data['decrypt_key']))

    def test_decrypt(self):
        for data in self.sample_data:
            jwe = deserialize(data['compact_serialization'])
            self.assertEqual(jwe.decrypt_with(data['decrypt_key']),
                    data['expected_payload'])
