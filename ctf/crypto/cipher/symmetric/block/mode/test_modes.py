from Crypto.Util.Padding import pad, unpad
import os
    

### Test Modes ###
key = os.urandom(16)
iv = os.urandom(16)
nonce = os.urandom(8)


from Crypto.Cipher import DES
from Crypto.Cipher import AES


from ecb import ECB
from cbc import CBC
from cfb import CFB
from ofb import OFB
from ctr import CTR


Enc = AES

block = Enc.new(key, AES.MODE_ECB)

tests = []

tests.append([
    lambda : Enc.new(key, AES.MODE_ECB), ECB(block, key), True
])
tests.append([
    lambda : Enc.new(key, AES.MODE_CBC, iv=iv), CBC(block, key, iv=iv), True
])
tests.append([
    lambda : Enc.new(key, AES.MODE_CFB, iv=iv), CFB(block, key, iv=iv), False
])
tests.append([
    lambda : Enc.new(key, AES.MODE_OFB, iv=iv), OFB(block, key, iv=iv), False
])
tests.append([
    lambda : Enc.new(key, AES.MODE_CTR, nonce=nonce), CTR(block, key, nonce=nonce), False
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
