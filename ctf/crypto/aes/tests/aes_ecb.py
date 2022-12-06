def pad(msg: bytes): # pkcs#7 pad implementation
	pad_len = (16 - len(msg)) % 16
	if pad_len == 0: pad_len = 16
	return msg + bytes([pad_len]*pad_len)

def unpad(msg: bytes): # pkcs#7 unpad implementation
	pad_len = msg[-1]
	if not all(msg[-i-1] == pad_len for i in range(pad_len)):
		raise Exception("Wrong padding")
	return msg[:-pad_len]

from Crypto.Cipher import AES
import os

class AES_ECB:
    def __init__(self, key: bytes):
        self.aes = AES.new(key, AES.MODE_ECB)

    def encrypt(self, msg: bytes):
        enc = b''
        for i in range(0,len(msg),16):
            enc += self.aes.encrypt(msg[i:i+16])
        return enc

    def decrypt(self, enc: bytes):
        msg = b''
        for i in range(0,len(enc),16):
            msg += self.aes.decrypt(enc[i:i+16])
        return msg
    
key = os.urandom(16) # generate 16 byte key
msg = pad(b'This is the messaege that will be encrypted')

aes = AES_ECB(key)

### Encryption ###
enc = aes.encrypt(msg)

aes_ = AES.new(key, AES.MODE_ECB)
enc_ = aes_.encrypt(msg)
assert enc_ == enc

### Decryption ###
decr = aes.decrypt(enc)

aes_ = AES.new(key, AES.MODE_ECB)
decr_ = aes_.decrypt(enc_)
assert decr == decr_
