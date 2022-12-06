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

key = os.urandom(16) # generate 16 byte key
aes = AES.new(key, AES.MODE_ECB)

msg = b'Encrypt this'

padded = pad(msg)
assert len(padded) % 16 == 0

### Encryption ###
enc = aes.encrypt(padded)

### Decryption ###
msg_ = unpad(aes.decrypt(enc))

assert msg == msg_
print(msg_)
