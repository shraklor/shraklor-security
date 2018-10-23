'''
wrapper to make hasing a little easier

Author: shraklor
Target: Python 3.6
'''
import M2Crypto

class Hashing():
    '''
    class to manage hashing strings and files
    '''
    SUPPORTED_ALGORITHMS = ['md5', 'sha1', 'sha256', 'sha512']
    CHUNK_SIZE = 4096

    def __init__(self, algorithm):
        if algorithm not in self.SUPPORTED_ALGORITHMS:
            raise ValueError('Unsupported algorithm [{0}]'.format(algorithm))

        self._alg = algorithm


    @staticmethod
    def _string_to_bytes(value):
        '''
        converts string to byte array
        '''
        return bytes([ord(c) for c in value])


    def hash(self, value):
        '''
        main process to convert string to hash
        '''
        text = self._string_to_bytes(value)
        cipher = M2Crypto.EVP.MessageDigest(self._alg)
        cipher.update(text)
        results = cipher.final()
        del cipher

        return results.hex()


    def hashfile(self, filename):
        '''
        main process for hashing file contents
        '''
        results = None

        with open(filename, 'rb') as hwd:
            cipher = M2Crypto.EVP.MessageDigest(self._alg)
            for chunk in iter(lambda: hwd.read(self.CHUNK_SIZE, b'')):
                cipher.update(chunk)
            results = cipher.final()
            del cipher

        return results.hex()


    @staticmethod
    def MD5(value): #pylint: disable=C0103
        '''
        static helper to convert string to MD5
        '''
        return Hashing('md5').hash(value)

    @staticmethod
    def SHA1(value): #pylint: disable=C0103
        '''
        static helper to convert string to sha1
        '''
        return Hashing('sha1').hash(value)

    @staticmethod
    def SHA256(value): #pylint: disable=C0103
        '''
        static helper to convert string to sha256
        '''
        return Hashing('sha256').hash(value)


    @staticmethod
    def SHA512(value): #pylint: disable=C0103
        '''
        static helper to convert string to sha512
        '''
        return Hashing('sha512').hash(value)


    @staticmethod
    def MD5File(filename): #pylint: disable=C0103
        '''
        static helper to convert file contents to MD5
        '''
        return Hashing('md5').hashfile(filename)

    @staticmethod
    def SHA1File(filename): #pylint: disable=C0103
        '''
        static helper to convert file contents to sha1
        '''
        return Hashing('sha1').hashfile(filename)

    @staticmethod
    def SHA256File(filename): #pylint: disable=C0103
        '''
        static helper to convert file contents to sha256
        '''
        return Hashing('sha256').hashfile(filename)


    @staticmethod
    def SHA512File(filename): #pylint: disable=C0103
        '''
        static helper to convert file contents to sha512
        '''
        return Hashing('sha512').hashfile(filename)
