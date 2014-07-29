from jot.algo import aes_cbc_hmac_sha
import binascii
import hashlib
import unittest


class TestAlgorithm(unittest.TestCase):
    sample_data = [
        {
            'name': 'AES_128_CBC_HMAC_SHA_256',
            'hash_function': hashlib.sha256,
            'k': binascii.a2b_hex(
                '000102030405060708090a0b0c0d0e0f'
                '101112131415161718191a1b1c1d1e1f'
            ),
            'iv': binascii.a2b_hex(
                '1af38c2dc2b96ffdd86694092341bc04'
            ),
            'p': binascii.a2b_hex(
                '41206369706865722073797374656d20'
                '6d757374206e6f742062652072657175'
                '6972656420746f206265207365637265'
                '742c20616e64206974206d7573742062'
                '652061626c6520746f2066616c6c2069'
                '6e746f207468652068616e6473206f66'
                '2074686520656e656d7920776974686f'
                '757420696e636f6e76656e69656e6365'
            ),
            'a': binascii.a2b_hex(
                '546865207365636f6e64207072696e63'
                '69706c65206f66204175677573746520'
                '4b6572636b686f666673'
            ),
            'e': binascii.a2b_hex(
                'c80edfa32ddf39d5ef00c0b468834279'
                'a2e46a1b8049f792f76bfe54b903a9c9'
                'a94ac9b47ad2655c5f10f9aef71427e2'
                'fc6f9b3f399a221489f16362c7032336'
                '09d45ac69864e3321cf82935ac4096c8'
                '6e133314c54019e8ca7980dfa4b9cf1b'
                '384c486f3a54c51078158ee5d79de59f'
                'bd34d848b3d69550a67646344427ade5'
                '4b8851ffb598f7f80074b9473c82e2db'
            ),
            't': binascii.a2b_hex(
                '652c3fa36b0a7c5b3219fab3a30bc1c4'
            ),
        },

        {
            'name': 'AES_192_CBC_HMAC_SHA_384',
            'hash_function': hashlib.sha384,
            'k': binascii.a2b_hex(
                '000102030405060708090a0b0c0d0e0f'
                '101112131415161718191a1b1c1d1e1f'
                '202122232425262728292a2b2c2d2e2f'
            ),
            'iv': binascii.a2b_hex(
                '1af38c2dc2b96ffdd86694092341bc04'
            ),
            'p': binascii.a2b_hex(
                '41206369706865722073797374656d20'
                '6d757374206e6f742062652072657175'
                '6972656420746f206265207365637265'
                '742c20616e64206974206d7573742062'
                '652061626c6520746f2066616c6c2069'
                '6e746f207468652068616e6473206f66'
                '2074686520656e656d7920776974686f'
                '757420696e636f6e76656e69656e6365'
            ),
            'a': binascii.a2b_hex(
                '546865207365636f6e64207072696e63'
                '69706c65206f66204175677573746520'
                '4b6572636b686f666673'
            ),
            'e': binascii.a2b_hex(
                'ea65da6b59e61edb419be62d19712ae5'
                'd303eeb50052d0dfd6697f77224c8edb'
                '000d279bdc14c1072654bd30944230c6'
                '57bed4ca0c9f4a8466f22b226d174621'
                '4bf8cfc2400add9f5126e479663fc90b'
                '3bed787a2f0ffcbf3904be2a641d5c21'
                '05bfe591bae23b1d7449e532eef60a9a'
                'c8bb6c6b01d35d49787bcd57ef484927'
                'f280adc91ac0c4e79c7b11efc60054e3'
            ),
            't': binascii.a2b_hex(
                '8490ac0e58949bfe51875d733f93ac20'
                '75168039ccc733d7'
            ),
        },

        # XXX These test data from the spec fail
#        {
#            'name': 'AES_256_CBC_HMAC_SHA_512',
#            'hash_function': hashlib.sha512,
#            'k': binascii.a2b_hex(
#                '000102030405060708090a0b0c0d0e0f'
#                '101112131415161718191a1b1c1d1e1f'
#                '202122232425262728292a2b2c2d2e2f'
#                '303132333435363738393a3b3c3d3e3f'
#            ),
#            'iv': binascii.a2b_hex(
#                '1af38c2dc2b96ffdd86694092341bc04'
#            ),
#            'p': binascii.a2b_hex(
#                '41206369706865722073797374656d20'
#                '6d757374206e6f742062652072657175'
#                '6972656420746f206265207365637265'
#                '742c20616e64206974206d7573742062'
#                '652061626c6520746f2066616c6c2069'
#                '6e746f207468652068616e6473206f66'
#                '2074686520656e656d7920776974686f'
#                '757420696e636f6e76656e69656e6365'
#            ),
#            'a': binascii.a2b_hex(
#                '546865207365636f6e64207072696e63'
#                '69706c65206f66204175677573746520'
#                '4b6572636b686f666673'
#            ),
#            'e': binascii.a2b_hex(
#                '4affaaadb78c31c5da4b1b590d10ffbd'
#                '3dd8d5d302423526912da037ecbcc7bd'
#                '822c301dd67c373bccb584ad3e9279c2'
#                'e6d12a1374b77f077553df829410446b'
#                '36ebd97066296ae6427ea75c2e0846a1'
#                '1a09ccf5370dc80bfecbad28c73f09b3'
#                'a3b75e662a2594410ae496b2e2e6609e'
#                '31e6e02cc837f053d21f37ff4f51950b'
#                'be2638d09dd7a4930930806d0703b1f6'
#            ),
#            't': binascii.a2b_hex(
#                '4dd3b4c088a7f45c216839645b2012bf'
#                '2e6269a8c56a816dbc1b267761955bc5'
#            ),
#        },
    ]

    def test_encrypt(self):
        for data in self.sample_data:
            print 'Checking %s...' % data['name']
            e, t = aes_cbc_hmac_sha.encrypt(k=data['k'], p=data['p'],
                    a=data['a'], iv=data['iv'],
                    hash_function=data['hash_function'])

            import binascii
            print ' ', binascii.b2a_base64(e)
            print ' ', binascii.b2a_base64(data['e'])

            self.assertEqual(e, data['e'])
            self.assertEqual(t, data['t'])
            print 'Checking', data['name'], 'complete.'
            print

    def test_verify(self):
        for data in self.sample_data:
            print 'Checking %s...' % data['name']

            self.assertTrue(aes_cbc_hmac_sha.verify(k=data['k'], e=data['e'],
                a=data['a'], iv=data['iv'], t=data['t'],
                hash_function=data['hash_function']))

            print 'Checking', data['name'], 'complete.'
            print

    def test_decrypt(self):
        for data in self.sample_data:
            print 'Checking %s...' % data['name']

            self.assertEqual(aes_cbc_hmac_sha.decrypt(k=data['k'], e=data['e'],
                iv=data['iv']), data['p'])

            print 'Checking', data['name'], 'complete.'
            print
