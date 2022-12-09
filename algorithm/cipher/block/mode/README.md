# Block Modes

## Links
* [Wikipedia: Block cipher mode of operation](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation)
- [pycryptodome documentation for modes](https://pycryptodome.readthedocs.io/en/latest/src/cipher/classic.html)

## Classic modes

### Electronic CodeBook (ECB)

```python
class ECB:
    def __init__(self, cipher):
        self.cipher = cipher # .encrypt(), .decrypt()
        self.block_size = cipher.block_size

    def encrypt(self, msg: bytes):
        enc = b''
        for i in range(0,len(msg),self.block_size):
            enc += self.cipher.encrypt(msg[i:i+self.block_size])
        return enc

    def decrypt(self, enc: bytes):
        msg = b''
        for i in range(0,len(enc),self.block_size):
            msg += self.cipher.decrypt(enc[i:i+self.block_size])
        return msg
```

### Ciphertext Block Chaining (CBC)

```python
def xor(x:bytes, y:bytes):
    return bytes([x_^y_ for x_,y_ in zip(x,y)])

class CBC:
    def __init__(self, cipher, iv: bytes):
        self.cipher = cipher # .encrypt(), .decrypt()
        self.block_size = cipher.block_size
        self.iv = iv

    def encrypt(self, msg: bytes):
        enc = self.iv
        for i in range(0, len(msg), self.block_size):
            blk_xor_prevenc = xor(enc[i:i+self.block_size],
                                  msg[i:i+self.block_size])
            enc += self.cipher.encrypt(blk_xor_prevenc)
        return enc[self.block_size:]

    def decrypt(self, enc: bytes):
        enc = self.iv + enc
        msg = b''
        for i in range(self.block_size,len(enc),self.block_size):
            encblk = enc[i:i+self.block_size]
            blk_xor_prevenc = self.cipher.decrypt(encblk)
            msg += xor(enc[i-self.block_size:i], blk_xor_prevenc)
        return msg
```

### Cipher FeedBack (CFB)
```python
class CFB:
    def __init__(self, cipher, iv: bytes):
        self.cipher = cipher # .encrypt(), .decrypt()
        self.iv = iv

    def encrypt(self, msg: bytes):
        state = self.iv
        enc = b''
        for i in range(0,len(msg)):
            enc_state = self.cipher.encrypt(state)
            enc += bytes([enc_state[0] ^ msg[i]])
            state = state[1:] + bytes([enc[-1]])
        return enc

    def decrypt(self, enc: bytes):
        state = self.iv
        msg = b''
        for i in range(0,len(enc)):
            enc_state = self.cipher.encrypt(state)
            msg += bytes([enc_state[0] ^ enc[i]])
            state = state[1:] + bytes([enc[i]])
        return msg
```

### Output FeedBack (OFB)
```python
def xor(x:bytes, y:bytes):
    return bytes([x_^y_ for x_,y_ in zip(x,y)])

class OFB:
    def __init__(self, cipher, iv: bytes):
        self.cipher = cipher # .encrypt(), .decrypt()
        self.block_size = cipher.block_size
        self.iv = iv

    def encrypt(self, msg: bytes):
        tmp = self.iv
        enc = b''
        for i in range(0,len(msg), self.block_size):
            enc_tmp = self.cipher.encrypt(tmp)
            enc += xor(enc_tmp, msg[i:i+self.block_size])
            tmp = enc_tmp
        return enc

    def decrypt(self, enc: bytes):
        tmp = self.iv
        msg = b''
        for i in range(0,len(enc), self.block_size):
            enc_tmp = self.cipher.encrypt(tmp)
            msg += xor(enc_tmp, enc[i:i+self.block_size])
            tmp = enc_tmp
        return msg
```

### CounTeR (CTR)
```python
def xor(x:bytes, y:bytes):
    return bytes([x_^y_ for x_,y_ in zip(x,y)])

class CTR:
    def __init__(self, cipher, nonce: bytes):
        self.cipher = cipher # .encrypt(), .decrypt()
        self.block_size = cipher.block_size
        self.nonce = nonce

    def encrypt(self, msg: bytes):
        counter = 0
        enc = b''
        for i in range(0,len(msg),self.block_size):
            c = self.nonce + counter.to_bytes(len(self.nonce),'big')
            enc_tmp = self.cipher.encrypt(c)
            enc += xor(enc_tmp, msg[i:i+self.block_size])
            counter += 1
        return enc

    def decrypt(self, enc: bytes):
        counter = 0
        msg = b''
        for i in range(0,len(enc),self.block_size):
            c = self.nonce + counter.to_bytes(len(self.nonce),'big')
            enc_tmp = self.cipher.encrypt(c)
            msg += xor(enc_tmp, enc[i:i+self.block_size])
            counter += 1
        return msg
```

### OpenPGP

## Modern Modes

### Counter with CBC-MAC (CCM)

### EAX

### Galois/Counter Mode (GCM)

### Synthetic Initialization Vector (SIV)

### Offset CodeBook (OCB)
