'''
wrapper to make encrypting/decrypting a little easier

Author: shraklor
Target: Python 3.6
'''
from io import BytesIO
import M2Crypto


def _bytes_to_string(binary):
    return "".join(chr(b) for b in binary)


class Cryptography():
    '''
    class for encrypting/decrypting strings


    '''

    _DEFAULT_KEY = 'THIS IS TOO SIMPLE'
    _DEFAULT_VECTOR = 'SO IS THIS'
    _DEFAULT_SALT = 'CHANGE THESE'

    SUPPORTED_ALGORITHMS = ['aes_128_cbc',
                            'des_ede_cbc',
                            'des_ede3_cbc',
                            'aes_256_cbc',
                            'bf_cbc']

    def __init__(self, algorithm, salt=None, iv=None, key=None):
        '''
        init
        '''
        if algorithm not in self.SUPPORTED_ALGORITHMS:
            raise ValueError('Unsupported algorithm [{0}]'.format(algorithm))

        self.alg = algorithm

        if not key:
            key = self._DEFAULT_KEY

        if not iv is None:
            iv = self._DEFAULT_VECTOR

        if not salt:
            salt = self._DEFAULT_SALT

        self.key = key
        self.vector = iv
        self.salt = salt

    @staticmethod
    def _string_to_bytes(text):
        '''
        converts text to bytes
        '''
        return bytes([ord(c) for c in text])


    @staticmethod
    def _cipher_filter(cipher, data):
        '''
        converts data using M2Crypto cipher
        '''
        instream = BytesIO(data)
        outstream = BytesIO()

        while True:
            _buffer = instream.read()
            if not _buffer:
                break
            outstream.write(cipher.update(_buffer))
        outstream.write(cipher.final())
        results = outstream.getvalue()

        instream.close()
        outstream.close()

        return results


    def _get_cipher(self, operation):
        '''
        get appropriate M2Crypto cipher based on instance values
        '''
        key = self._string_to_bytes(self.key)
        vector = self._string_to_bytes(self.vector)
        salt = self._string_to_bytes(self.salt)

        return M2Crypto.EVP.Cipher(alg=self.alg, key=key,
                                   iv=vector, op=operation, key_as_bytes=1,
                                   d='sha1', salt=salt, i=5, padding=1)


    def encrypt(self, plaintext):
        '''
        encrypts plaintext value based on instance algorithm, IV, and key
        '''
        operation = 1

        text = self._string_to_bytes(plaintext)
        cipher = self._get_cipher(operation)
        results = self._cipher_filter(cipher, text)
        del cipher

        return results.hex()


    def decrypt(self, ciphertext):
        '''
        decrypts plaintext value based on instance algorithm, IV, and key
        '''
        operation = 0

        text = bytes.fromhex(ciphertext)
        cipher = self._get_cipher(operation)
        results = self._cipher_filter(cipher, text)
        del cipher

        return results.decode()


    @staticmethod
    def Encrypt(algorithm, salt, iv, key, plaintext): # pylint: disable=C0103
        '''
        static version
        '''
        return Cryptography(algorithm, key=key, iv=iv, salt=salt).encrypt(plaintext)


    @staticmethod
    def Decrypt(algorithm, salt, iv, key, ciphertext): # pylint: disable=C0103
        '''
        static version
        '''
        return Cryptography(algorithm, key=key, iv=iv, salt=salt).decrypt(ciphertext)
