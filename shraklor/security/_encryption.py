'''
wrapper to make encrypting/decrypting a little easier

Author: shraklor
Target: Python 3.6
'''
import logging
import M2Crypto
from io import BytesIO

class Hashing():
    '''
    '''
    SUPPORTED_ALGORITHMS = ['md5', 'sha1', 'sha256', 'sha512']

    def __init__(self, algorithm, iv, key):
        if algorithm not in self.SUPPORTED_ALGORITHMS:
            raise ValueError('Unsupported algorithm [{0}]'.format(algorithm))

        self.alg = algorithm


    def hash(self, value):
        pass


def _string_to_bytes(text):
    return list(ord(c) for c in text)

def _bytes_to_string(binary):
    return "".join(chr(b) for b in binary)


class Cryptography():
    '''

    '''

    SUPPORTED_ALGORITHMS = ['aes_128_cbc', 'des_ede_cbc', 'des_ede3_cbc', 'aes_256_cbc', 'bf_cbc']

    def __init__(self, algorithm, salt=None, iv=None, key=None):
        '''

        '''
        if algorithm not in self.SUPPORTED_ALGORITHMS:
            raise ValueError('Unsupported algorithm [{0}]'.format(algorithm))

        self.alg = algorithm

        if key is None:
            key = b'YouShouldProvideYourOwnKeyToMakeThisSecure'

        if iv is None:
            iv = b'YouShouldProvideYourOwnIvToMakeThisSecure'

        if salt is None:
            salt = b'YouShouldProvideYourOwnSaltToMakeThisSecure'

        self.key = key
        self.iv = iv
        self.salt = salt


    @staticmethod
    def _cipher_filter(cipher, data):
        '''

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

    def _get_cipher(self, op):
        '''
        get appropriate M2Crypto cipher based on instance values
        '''
        return M2Crypto.EVP.Cipher(alg=self.alg, key=self.key,
                                    iv=self.iv, op=op, key_as_bytes=1,
                                    d='sha1', salt=self.salt, i=5, padding=1)


    def encrypt(self, plaintext):
        '''
        encrypts plaintext value based on instance algorithm, IV, and key
        '''
        ENCRYPT = 1

        cipher = self._get_cipher(ENCRYPT)
        results = self._cipher_filter(cipher, plaintext)
        del cipher


        #print('encrypt()')
        #print('encrypt({0})'.format(results))
        #print('encrypt({0})'.format(_bytes_to_string(results)))
        return results.hex()


    def decrypt(self, ciphertext):
        '''
        decrypts plaintext value based on instance algorithm, IV, and key
        '''
        DECRYPT = 0

        ciphertext = bytes.fromhex(ciphertext)
        cipher = self._get_cipher(DECRYPT)
        results = self._cipher_filter(cipher, ciphertext)
        del cipher

        #print('decrypt' + _bytes_to_string(results))
        return results


    @staticmethod
    def Encrypt(algorithm, salt, iv, key, plaintext):
        '''
        '''
        return Cryptography(algorithm, key=key, iv=iv, salt=salt).encrypt(plaintext)


    @staticmethod
    def Decrypt(algorithm, salt, iv, key, ciphertext):
        '''
        '''
        return Cryptography(algorithm, key=key, iv=iv, salt=salt).decrypt(ciphertext)



if __name__ == '__main__':
    SOURCE = 'Brad Was Here To Test How Well This Gets Encrypted'.encode('utf-8')
    KEY = b'None'
    IV = b'None'
    SALT = b'None'

    OTXT = SOURCE
    for ALGO in ['des_ede_cbc', 'des_ede3_cbc', 'aes_128_cbc', 'aes_256_cbc', 'bf_cbc']:
        CTXT = Cryptography.Encrypt(ALGO, SALT, IV, KEY, OTXT)
        PTXT = Cryptography.Decrypt(ALGO, SALT, IV, KEY, CTXT)

        CRYPTOR = Cryptography(algorithm=ALGO, salt=SALT, key=KEY, iv=IV)
        CTXT = CRYPTOR.encrypt(PTXT)
        PTXT = CRYPTOR.decrypt(CTXT)
        del CRYPTOR

    if OTXT == PTXT:
        print(CTXT)
        print(PTXT.decode())
        print('Still matches!!')

