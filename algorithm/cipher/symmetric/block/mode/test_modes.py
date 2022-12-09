from Crypto.Util.Padding import pad, unpad
import os
    

### Test Modes ###


from Crypto.Cipher import DES
from Crypto.Cipher import AES


from ecb import ECB
from cbc import CBC
from cfb import CFB
from ofb import OFB
from ctr import CTR

ENC = [[AES, 16], [DES, 8]]

for Enc, key_len in ENC:
    key = os.urandom(key_len)
    iv = os.urandom(key_len)
    nonce = os.urandom(key_len//2)

    cipher = Enc.new(key, AES.MODE_ECB)

    tests = []

    tests.append([
        lambda : Enc.new(key, AES.MODE_ECB), ECB(cipher), True
    ])
    tests.append([
        lambda : Enc.new(key, AES.MODE_CBC, iv=iv), CBC(cipher, iv=iv), True
    ])
    tests.append([
        lambda : Enc.new(key, AES.MODE_CFB, iv=iv), CFB(cipher, iv=iv), False
    ])
    tests.append([
        lambda : Enc.new(key, AES.MODE_OFB, iv=iv), OFB(cipher, iv=iv), False
    ])
    tests.append([
        lambda : Enc.new(key, AES.MODE_CTR, nonce=nonce), CTR(cipher, nonce=nonce), False
    ])

    for correct, test, padding in tests:
        for i in range(1000):
            msg = b'a'*i
            if padding: msg = pad(msg, test.block_size)
            encc = correct().encrypt(msg)
            enct = test.encrypt(msg)
            assert encc==enct, f"{test = }, ({encc = }) != ({enct = })"
            decrc = correct().decrypt(encc)
            decrt = test.decrypt(enct)
            assert decrc == decrt


print("All tests have finished correctly")
