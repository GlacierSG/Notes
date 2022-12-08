# AES Encryption

AES is a block cipher that uses 16 byte block sizes

## Using

- [python3](https://www.python.org)
	- [pycryptodome](https://www.pycryptodome.org/)

## Links

* [Explanation of 5 basic AES modes (With illustrations)](https://www.highgo.ca/2019/08/08/the-difference-in-five-modes-in-the-aes-encryption-algorithm/)
* [Rust implementation of some AES modes (with illustrations)](https://github.com/RustCrypto/block-modes)

## Basic Implementation

Since AES can only encrypt 16 byte blocks, you need to make sure you pad your message to be a multiple of 16 bytes before encryption (Except for modes that turn it into stream ciphers). There are a lot of ways to pad your message, but a common one is [PKCS#7](https://en.wikipedia.org/wiki/Padding_(cryptography)#PKCS#5_and_PKCS#7)



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

[pycryptodome](https://www.pycryptodome.org/) implements these AES modes

```python
AES.new(key, AES.MODE_ECB)
AES.new(key, AES.MODE_CBC, iv=iv)
AES.new(key, AES.MODE_CFB, iv=iv)
AES.new(key, AES.MODE_OFB, iv=iv)
AES.new(key, AES.MODE_CTR, nonce=nonce)
AES.new(key, AES.MODE_EAX, ?)
AES.new(key, AES.MODE_GCM, ?)
AES.new(key, AES.MODE_SIV, ?)
AES.new(key, AES.MODE_CCM, ?)
AES.new(key, AES.MODE_OCB, ?)
AES.new(key, AES.MODE_OPENPGP, ?)
```

