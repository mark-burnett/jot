from . import spec_keys
from Crypto.PublicKey import RSA
from jot import deserialize, jose
from jot.codec import base64url_decode
import jot
import unittest


PRIVATE_KEY = RSA.importKey('''-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----''')


PUBLIC_KEY= PRIVATE_KEY.publickey()


class TestEncryptionConsistency(unittest.TestCase):
    sample_data = [
        {
            'encrypt_alg': 'RSA1_5',
            'encrypt_enc': 'A128CBC-HS256',
            'payload_class': jose.JOSEString,
            'payload': 'this is a sample sequence to encrypt',
            'encrypt_key': PUBLIC_KEY,
            'decrypt_key': PRIVATE_KEY,
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
            'decrypt_key': spec_keys.jwe_private_key_2,
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


_NESTED_SERIALIZED_JWE = (
    'eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiY3R5IjoiSldU'
    'In0.'
    'g_hEwksO1Ax8Qn7HoN-BVeBoa8FXe0kpyk_XdcSmxvcM5_P296JXXtoHISr_DD_M'
    'qewaQSH4dZOQHoUgKLeFly-9RI11TG-_Ge1bZFazBPwKC5lJ6OLANLMd0QSL4fYE'
    'b9ERe-epKYE3xb2jfY1AltHqBO-PM6j23Guj2yDKnFv6WO72tteVzm_2n17SBFvh'
    'DuR9a2nHTE67pe0XGBUS_TK7ecA-iVq5COeVdJR4U4VZGGlxRGPLRHvolVLEHx6D'
    'YyLpw30Ay9R6d68YCLi9FYTq3hIXPK_-dmPlOUlKvPr1GgJzRoeC9G5qCvdcHWsq'
    'JGTO_z3Wfo5zsqwkxruxwA.'
    'UmVkbW9uZCBXQSA5ODA1Mg.'
    'VwHERHPvCNcHHpTjkoigx3_ExK0Qc71RMEParpatm0X_qpg-w8kozSjfNIPPXiTB'
    'BLXR65CIPkFqz4l1Ae9w_uowKiwyi9acgVztAi-pSL8GQSXnaamh9kX1mdh3M_TT'
    '-FZGQFQsFhu0Z72gJKGdfGE-OE7hS1zuBD5oEUfk0Dmb0VzWEzpxxiSSBbBAzP10'
    'l56pPfAtrjEYw-7ygeMkwBl6Z_mLS6w6xUgKlvW6ULmkV-uLC4FUiyKECK4e3WZY'
    'Kw1bpgIqGYsw2v_grHjszJZ-_I5uM-9RA8ycX9KqPRp9gc6pXmoU_-27ATs9XCvr'
    'ZXUtK2902AUzqpeEUJYjWWxSNsS-r1TJ1I-FMJ4XyAiGrfmo9hQPcNBYxPz3GQb2'
    '8Y5CLSQfNgKSGt0A4isp1hBUXBHAndgtcslt7ZoQJaKe_nNJgNliWtWpJ_ebuOpE'
    'l8jdhehdccnRMIwAmU1n7SPkmhIl1HlSOpvcvDfhUN5wuqU955vOBvfkBOh5A11U'
    'zBuo2WlgZ6hYi9-e3w29bR0C2-pp3jbqxEDw3iWaf2dc5b-LnR0FEYXvI_tYk5rd'
    '_J9N0mg0tQ6RbpxNEMNoA9QWk5lgdPvbh9BaO195abQ.'
    'AVO9iT5AV4CzvDJCdhSFlQ'
)

class TestNestedJWSJWE(unittest.TestCase):
    def test_spec_sample(self):
        jwe = deserialize(_NESTED_SERIALIZED_JWE)
        jws = jwe.verify_and_decrypt_with(spec_keys.jwe_private_key_2)
        self.assertTrue(jws.verify_with(spec_keys.jws_public_key))

        t = jws.payload
        self.assertEqual(dict(t), {
            'exp': 1300819380,
            'iss': 'joe',
            'http://example.com/is_root': True,
        })

    def test_round_trip(self):
        claims = {
            'iss': 'http://example.com/jwt/example',
            'claim1': 1,
            'claim2': ['foo', 'bar'],
        }

        begin_token = jot.Token(claims)
        begin_jws = begin_token.sign_with(spec_keys.jws_private_key,
                alg='RS256')
        begin_jwe = begin_jws.encrypt_with(spec_keys.jwe_public_key,
                alg='RSA1_5', enc='A128CBC-HS256')

        serialization = begin_jwe.compact_serialize()

        end_jwe = deserialize(serialization)
        end_jws = end_jwe.verify_and_decrypt_with(spec_keys.jwe_private_key)
        end_jws = end_jwe.verify_and_decrypt_with(spec_keys.jwe_private_key)

        self.assertTrue(end_jws.verify_with(spec_keys.jws_public_key))

        end_token = end_jws.payload
        self.assertIsInstance(end_token, jot.Token)
        self.assertEqual(end_token.claims, claims)
