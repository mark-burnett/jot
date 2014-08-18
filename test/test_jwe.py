from Crypto.PublicKey import RSA
from jot import deserialize, jose, JWE
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


class TestEncryptionConsistency(unittest.TestCase):
    sample_data = [
        {
#            'header': {'alg': 'RSA1_5', 'enc': 'A128CBC-HS256'},
            'encrypt_alg': 'RSA1_5',
            'encrypt_enc': 'A128CBC-HS256',
            'payload_class': jose.JOSEString,
            'payload': 'this is a sample sequence to encrypt',
            'encrypt_key': RSA.importKey(PUBLIC_KEY),
            'decrypt_key': RSA.importKey(PRIVATE_KEY),
        },

    ]

    def test_round_trip(self):
        for data in self.sample_data:
            jo = data['payload_class'](data['payload'])
            initial_jwe = jo.encrypt_with(data['encrypt_key'],
                    alg=data['encrypt_alg'], enc=data['encrypt_enc'])
            serialization = initial_jwe.compact_serialize()

            second_jwe = deserialize(serialization)
            payload = second_jwe.verify_and_decrypt_with(data['decrypt_key'])
            self.assertEqual(payload, jo)

    def test_ciphertext_different_each_time(self):
        for data in self.sample_data:
            jo = data['payload_class'](data['payload'])
            jwe1 = jo.encrypt_with(data['encrypt_key'],
                    alg=data['encrypt_alg'], enc=data['encrypt_enc'])
            jwe2 = jo.encrypt_with(data['encrypt_key'],
                    alg=data['encrypt_alg'], enc=data['encrypt_enc'])

            self.assertNotEqual(jwe1.ciphertext, jwe2.ciphertext)


SPEC_PRIV_KEY = RSA.construct((
    long(base64url_decode(
            'sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bOdgWp4Dy1'
            'WlUzewbgBHod5pcM9H95GQRV3JDXboIRROSBigeC5yjU1hGzHHyXss8UDprecbAYxk'
            'nTcQkhslANGRUZmdTOQ5qTRsLAt6BTYuyvVRdhS8exSZEy_c4gs_7svlJJQ4H9_Nxs'
            'iIoLwAEk7-Q3UXERGYw_75IDrGA84-lA_-Ct4eTlXHBIY2EaV7t7LjJaynVJCpkv4L'
            'KjTTAumiGUIuQhrNhZLuF_RJLqHpM2kgWFLU7-VTdL1VbC2tejvcI2BlMkEpk1BzBZ'
            'I0KQB0GaDWFLN-aEAw3vRw'
        ).encode('hex'), 16),
    long(base64url_decode('AQAB').encode('hex'), 16),
    long(base64url_decode(
            'VFCWOqXr8nvZNyaaJLXdnNPXZKRaWCjkU5Q2egQQpTBMwhprMzWzpR8Sx'
            'q1OPThh_J6MUD8Z35wky9b8eEO0pwNS8xlh1lOFRRBoNqDIKVOku0aZb-rynq8cxjD'
            'TLZQ6Fz7jSjR1Klop-YKaUHc9GsEofQqYruPhzSA-QgajZGPbE_0ZaVDJHfyd7UUBU'
            'KunFMScbflYAAOYJqVIVwaYR5zWEEceUjNnTNo_CVSj-VvXLO5VZfCUAVLgW4dpf1S'
            'rtZjSt34YLsRarSb127reG_DUwg9Ch-KyvjT1SkHgUWRVGcyly7uvVGRSDwsXypdrN'
            'inPA4jlhoNdizK2zF2CWQ'
        ).encode('hex'), 16)
    ))


class TestSpecSample(unittest.TestCase):
    sample_data = [
        {
            'compact_serialization':
                'eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.'
                'UGhIOguC7IuEvf_NPVaXsGMoLOmwvc1GyqlIKOK1nN94nHPoltGRhWhw7Zx0-kFm'
                '1NJn8LE9XShH59_i8J0PH5ZZyNfGy2xGdULU7sHNF6Gp2vPLgNZ__deLKxGHZ7Pc'
                'HALUzoOegEI-8E66jX2E4zyJKx-YxzZIItRzC5hlRirb6Y5Cl_p-ko3YvkkysZIF'
                'NPccxRU7qve1WYPxqbb2Yw8kZqa2rMWI5ng8OtvzlV7elprCbuPhcCdZ6XDP0_F8'
                'rkXds2vE4X-ncOIM8hAYHHi29NX0mcKiRaD0-D-ljQTP-cFPgwCp6X-nZZd9OHBv'
                '-B3oWh2TbqmScqXMR4gp_A.'
                'AxY8DCtDaGlsbGljb3RoZQ.'
                'KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY.'
                '9hH0vgRfYgPnAHOd8stkvw',
            'expected_header': {'alg': 'RSA1_5', 'enc': 'A128CBC-HS256'},
            'decrypt_key': SPEC_PRIV_KEY,
            'expected_payload': 'Live long and prosper.',
        },
        {
            'compact_serialization':
                'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.'
                '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ.'
                'AxY8DCtDaGlsbGljb3RoZQ.'
                'KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY.'
                'U0m_YmjN04DJvceFICbCVQ',
            'expected_header': {'alg': 'A128KW', 'enc': 'A128CBC-HS256'},
            'decrypt_key': base64url_decode('GawgguFyGrWKav7AX4VKUg'),
            'expected_payload': 'Live long and prosper.',
        },
    ]

    def test_header(self):
        for data in self.sample_data:
            jwe = deserialize(data['compact_serialization'])
            self.assertEqual(jwe.header, data['expected_header'])

    def test_decrypt(self):
        for data in self.sample_data:
            jwe = deserialize(data['compact_serialization'])
            result = jwe.verify_and_decrypt_with(data['decrypt_key'])
            self.assertEqual(result, data['expected_payload'])
