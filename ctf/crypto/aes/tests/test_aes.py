
### Test padding ###
import Crypto.Util.Padding as RealPad
import aes_pad as TestPad

for i in range(1000):
    msg = b'a'*i
    padr = RealPad.pad(msg, 16)
    padt = TestPad.pad(msg)
    assert padr == padt
    unpadr = RealPad.unpad(padr, 16)
    unpadt = TestPad.unpad(padt)
    assert unpadr == unpadt
    

### Test AES Modes ###
from Crypto.Cipher import AES
from aes_pad import pad, unpad
import os


key = os.urandom(16)
iv = os.urandom(16)

tests = []

from aes_ecb import AES_ECB
def AES_ECB_(): return AES.new(key, AES.MODE_ECB)
tests.append([
    AES_ECB_, AES_ECB(key)
])

from aes_cbc import AES_CBC
def AES_CBC_(): return AES.new(key, AES.MODE_CBC, iv=iv)
tests.append([
    AES_CBC_, AES_CBC(key,iv)
])

for correct, test in tests:
    for i in range(1000):
        msg = pad(b'a'*i)
        encc = correct().encrypt(msg)
        enct = test.encrypt(msg)
        assert encc==enct, f"{test = }, ({encc = }) != ({enct = })"
        decrc = correct().decrypt(encc)
        decrt = test.decrypt(enct)
        assert decrc == decrt


print("All tests have finished correctly")