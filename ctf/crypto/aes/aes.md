# AES Encryption

AES is a block cipher that uses 16 byte block sizes

## Using

- [python3](https://www.python.org)
	- [pycryptodome](https://www.pycryptodome.org/)

## Links

* [Explanation of 5 basic AES modes (With illustrations)](https://www.highgo.ca/2019/08/08/the-difference-in-five-modes-in-the-aes-encryption-algorithm/)

## Basic Implementation

Since AES can only encrypt 16 byte blocks, you need to make sure you pad your message to be a multiple of 16 bytes before encryption (Except for modes that turn it into stream ciphers). There are a lot of ways to pad your message, but a common one is [PKCS#7](https://en.wikipedia.org/wiki/Padding_(cryptography)#PKCS#5_and_PKCS#7)

```python
def pad(msg: bytes): # pkcs#7 pad implementation
    pad_len = (16 - len(msg)) % 16
    if pad_len == 0: pad_len = 16
    return msg + bytes([pad_len]*pad_len)

def unpad(msg: bytes): # pkcs#7 unpad implementation
    pad_len = msg[-1]
    if not all(msg[-i-1] == pad_len for i in range(pad_len)):
        raise Exception("Wrong padding")
    return msg[:-pad_len]
```


```python
from Crypto.Cipher import AES
import os

key = os.urandom(16) # generate 16 byte key
aes = AES.new(key, AES.MODE_ECB)

msg = b'This is the message that will be encrypted'

padded = pad(msg)
assert len(padded) % 16 == 0

### Encryption ###
enc = aes.encrypt(padded)

### Decryption ###
msg_ = unpad(aes.decrypt(enc))

assert msg == msg_
print(msg_)
```

### AES Modes

[pycryptodome](https://www.pycryptodome.org/) implements all different modes for AES

```python
AES.new(key, AES.MODE_ECB)
AES.new(key, AES.MODE_CBC, iv=iv)
AES.new(key, AES.MODE_CFB, iv=iv)
AES.new(key, AES.MODE_EAX, ?)
AES.new(key, AES.MODE_GCM, ?)
AES.new(key, AES.MODE_OFB, ?)
AES.new(key, AES.MODE_SIV, ?)
AES.new(key, AES.MODE_CCM, ?)
AES.new(key, AES.MODE_CTR, ?)
AES.new(key, AES.MODE_OCB, ?)
AES.new(key, AES.MODE_OPENPGP, ?)
```

#### ECB Mode

```python
from Crypto.Cipher import AES
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
```

#### CBC Mode

```python
from Crypto.Cipher import AES

def xor(x:bytes, y:bytes): 
    return bytes([x_^y_ for x_,y_ in zip(x,y)])

class AES_CBC:
    def __init__(self, key: bytes, iv: bytes):
        self.aes = AES.new(key, AES.MODE_ECB)
        self.iv = iv # 16 byte iv

    def encrypt(self, msg: bytes):
        enc = self.iv
        for i in range(0,len(msg),16):
            blk_xor_prevenc = xor(enc[i:i+16], msg[i:i+16])
            enc += self.aes.encrypt(blk_xor_prevenc)
        return enc[16:]

    def decrypt(self, enc: bytes):
        enc = self.iv + enc
        msg = b''
        for i in range(16,len(enc),16):
            blk_xor_prevenc = self.aes.decrypt(enc[i:i+16])
            msg += xor(enc[i-16:i], blk_xor_prevenc)
        return msg
```

#### CFB Mode

```python
from Crypto.Cipher import AES

class AES_CFB:
    def __init__(self, key: bytes, iv: bytes):
        self.aes = AES.new(key, AES.MODE_ECB)
        self.iv = iv # 16 byte iv

    def encrypt(self, msg: bytes):
        tmp = self.iv
        enc = b''
        for i in range(0,len(msg)):
            enc_tmp = self.aes.encrypt(tmp)
            enc += bytes([enc_tmp[0] ^ msg[i]])
            tmp = tmp[1:] + bytes([enc[-1]])
        return enc

    def decrypt(self, enc: bytes):
        tmp = self.iv
        msg = b''
        for i in range(0,len(enc)):
            enc_tmp = self.aes.encrypt(tmp)
            msg += bytes([enc_tmp[0] ^ enc[i]])
            tmp = tmp[1:] + bytes([enc[i]])
        return msg 
```



