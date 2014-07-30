from jot.algo.aes_keywrap import wrap, unwrap
import binascii
import unittest


class TestAESKeyWrapAlgorithm(unittest.TestCase):
    sample_data = [
        {
            'kek': binascii.a2b_hex('000102030405060708090A0B0C0D0E0F'),
            'plaintext': binascii.a2b_hex('00112233445566778899AABBCCDDEEFF'),
            'ciphertext': binascii.a2b_hex(
                '1FA68B0A8112B447'
                'AEF34BD8FB5A7B82'
                '9D3E862371D2CFE5'
            ),
        },

        {
            'kek': binascii.a2b_hex('000102030405060708090A0B0C0D0E0F1011121314151617'),
            'plaintext': binascii.a2b_hex('00112233445566778899AABBCCDDEEFF'),
            'ciphertext': binascii.a2b_hex(
                '96778B25AE6CA435'
                'F92B5B97C050AED2'
                '468AB8A17AD84E5D'
            ),
        },

        {
            'kek': binascii.a2b_hex(
                '000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F'),
            'plaintext': binascii.a2b_hex('00112233445566778899AABBCCDDEEFF'),
            'ciphertext': binascii.a2b_hex(
                '64E8C3F9CE0F5BA2'
                '63E9777905818A2A'
                '93C8191E7D6E8AE7'
            ),
        },

        {
            'kek': binascii.a2b_hex(
                '000102030405060708090A0B0C0D0E0F1011121314151617'),
            'plaintext': binascii.a2b_hex(
                '00112233445566778899AABBCCDDEEFF0001020304050607'),
            'ciphertext': binascii.a2b_hex(
                '031D33264E15D332'
                '68F24EC260743EDC'
                'E1C6C7DDEE725A93'
                '6BA814915C6762D2'
            ),
        },

        {
            'kek': binascii.a2b_hex(
                '000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F'),
            'plaintext': binascii.a2b_hex(
                '00112233445566778899AABBCCDDEEFF0001020304050607'),
            'ciphertext': binascii.a2b_hex(
                'A8F9BC1612C68B3F'
                'F6E6F4FBE30E71E4'
                '769C8B80A32CB895'
                '8CD5D17D6B254DA1'
            ),
        },

        {
            'kek': binascii.a2b_hex(
                '000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F'),
            'plaintext': binascii.a2b_hex(
                '00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F'),
            'ciphertext': binascii.a2b_hex(
                '28C9F404C4B810F4'
                'CBCCB35CFB87F826'
                '3F5786E2D80ED326'
                'CBC7F0E71A99F43B'
                'FB988B9B7A02DD21'
            ),
        },

    ]

    def test_wrap(self):
        for data in self.sample_data:
            ciphertext = wrap(data['kek'], data['plaintext'])
            self.assertEqual(ciphertext, data['ciphertext'])

    def test_unwrap(self):
        for data in self.sample_data:
            plaintext, iv = unwrap(data['kek'], data['ciphertext'])
            self.assertEqual(plaintext, data['plaintext'])
            self.assertEqual(iv, binascii.a2b_hex('A6A6A6A6A6A6A6A6'))
