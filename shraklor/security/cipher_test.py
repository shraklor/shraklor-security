'''
wrapper to make encrypting/decrypting a little easier

Author: shraklor
Target: Python 3.6
'''
import logging
import M2Crypto
from io import BytesIO

# taken from: https://github.com/mcepl/M2Crypto/blob/master/tests/test_evp.py
class CipherTest():

    def filter(self, cipher, in_stream, out_stream):
        while True:
            buf = in_stream.read()
            if not buf:
                break
            out_stream.write(cipher.update(buf))
        out_stream.write(cipher.final())
        return out_stream.getvalue()
        
    def test_algo(self, alg, otxt):
        ENC = 1
        DEC = 0

        pbuf = BytesIO(otxt)
        cbuf = BytesIO()

        k = M2Crypto.EVP.Cipher(alg, b'goethe', b'12345678', ENC, 1, 'sha1', b'saltsalt', 5)
        ctxt = self.filter(k, pbuf, cbuf)
        pbuf.close()
        cbuf.close()

        j = M2Crypto.EVP.Cipher(alg, b'goethe', b'12345678', DEC, 1, 'sha1', b'saltsalt', 5)
        pbuf = BytesIO()
        cbuf = BytesIO(ctxt)
        ptxt = self.filter(j, cbuf, pbuf)
        pbuf.close()
        cbuf.close()
    
        #print(ctxt.hex())
        #print(ctxt)
        #print(ptxt)
        #print('-----------------------------------------------------------')
        return otxt == ptxt



if __name__ == '__main__':
    otxt = b'against stupidity the gods themselves contend in vain'

    for ALGO in ['des_ede_cbc', 'des_ede3_cbc', 'aes_128_cbc', 'aes_256_cbc', 'bf_cbc']:
        test= CipherTest()
        result = test.test_algo(ALGO, otxt)
        del test

        if result is  True:
            print('test_algo matches')
        else:
            print('Failed for {0}'.format(ALGO))
