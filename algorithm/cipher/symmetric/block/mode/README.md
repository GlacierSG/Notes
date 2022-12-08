# Block Modes

## Links
* [Wikipedia: Block cipher mode of operation](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation)
- [pycryptodome documentation for modes](https://pycryptodome.readthedocs.io/en/latest/src/cipher/classic.html)

## ECB Mode
```python
class ECB:
    def __init__(self, block, key: bytes):
        self.block = block # .encrypt(), .decrypt()
        self.block_size = block.block_size

    def encrypt(self, msg: bytes):
        enc = b''
        for i in range(0,len(msg),self.block_size):
            enc += self.block.encrypt(msg[i:i+self.block_size])
        return enc

    def decrypt(self, enc: bytes):
        msg = b''
        for i in range(0,len(enc),self.block_size):
            msg += self.block.decrypt(enc[i:i+self.block_size])
        return msg
```

## CBC Mode
```python
def xor(x:bytes, y:bytes): 
    return bytes([x_^y_ for x_,y_ in zip(x,y)])

class CBC:
    def __init__(self, block, key: bytes, iv: bytes):
        self.block = block # .encrypt(), .decrypt()
        self.block_size = block.block_size
        self.iv = iv 

    def encrypt(self, msg: bytes):
        enc = self.iv
        for i in range(0, len(msg), self.block_size):
            blk_xor_prevenc = xor(enc[i:i+self.block_size], 
                                  msg[i:i+self.block_size])
            enc += self.block.encrypt(blk_xor_prevenc)
        return enc[self.block_size:]

    def decrypt(self, enc: bytes):
        enc = self.iv + enc
        msg = b''
        for i in range(self.block_size,len(enc),self.block_size):
            encblk = enc[i:i+self.block_size]
            blk_xor_prevenc = self.block.decrypt(encblk)
            msg += xor(enc[i-self.block_size:i], blk_xor_prevenc)
        return msg
```

## CFB Mode
```python
class CFB:
    def __init__(self, block, key: bytes, iv: bytes):
        self.block = block # .encrypt(), .decrypt()
        self.iv = iv 

    def encrypt(self, msg: bytes):
        state = self.iv
        enc = b''
        for i in range(0,len(msg)):
            enc_state = self.block.encrypt(state)
            enc += bytes([enc_state[0] ^ msg[i]])
            state = state[1:] + bytes([enc[-1]])
        return enc

    def decrypt(self, enc: bytes):
        state = self.iv
        msg = b''
        for i in range(0,len(enc)):
            enc_state = self.block.encrypt(state)
            msg += bytes([enc_state[0] ^ enc[i]])
            state = state[1:] + bytes([enc[i]])
        return msg 
```

## OFB Mode
```python
class CFB:
    def __init__(self, block, key: bytes, iv: bytes):
        self.block = block # .encrypt(), .decrypt()
        self.iv = iv 

    def encrypt(self, msg: bytes):
        state = self.iv
        enc = b''
        for i in range(0,len(msg)):
            enc_state = self.block.encrypt(state)
            enc += bytes([enc_state[0] ^ msg[i]])
            state = state[1:] + bytes([enc[-1]])
        return enc

    def decrypt(self, enc: bytes):
        state = self.iv
        msg = b''
        for i in range(0,len(enc)):
            enc_state = self.block.encrypt(state)
            msg += bytes([enc_state[0] ^ enc[i]])
            state = state[1:] + bytes([enc[i]])
        return msg 
```

## CTR Mode
```python
def xor(x:bytes, y:bytes): 
    return bytes([x_^y_ for x_,y_ in zip(x,y)])

class CTR:
    def __init__(self, block, key: bytes, nonce: bytes):
        self.block = block # .encrypt(), .decrypt()
        self.block_size = block.block_size
        self.nonce = nonce

    def encrypt(self, msg: bytes):
        counter = 0
        enc = b''
        for i in range(0,len(msg),self.block_size):
            c = self.nonce + counter.to_bytes(len(self.nonce),'big')
            enc_tmp = self.block.encrypt(c)
            enc += xor(enc_tmp, msg[i:i+self.block_size])
            counter += 1
        return enc

    def decrypt(self, enc: bytes):
        counter = 0
        msg = b''
        for i in range(0,len(enc),self.block_size):
            c = self.nonce + counter.to_bytes(len(self.nonce),'big')
            enc_tmp = self.block.encrypt(c)
            msg += xor(enc_tmp, enc[i:i+self.block_size])
            counter += 1
    return msg 
```