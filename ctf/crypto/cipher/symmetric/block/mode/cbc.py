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

if __name__ == '__main__':
    from Crypto.Util.Padding import pad, unpad
    from Crypto.Cipher import AES
    import os

    key = os.urandom(16) # generate 16 byte key
    iv = os.urandom(16) # generate 16 byte iv
    msg = pad(b'This is the message that will be encrypted',16)

    aes = CBC(AES.new(key, AES.MODE_ECB), key, iv)

    ### Encryption ###
    enc = aes.encrypt(msg)

    aes_ = AES.new(key, AES.MODE_CBC, iv=iv)
    enc_ = aes_.encrypt(msg)

    assert enc_ == enc

    ### Decryption ###
    decr = aes.decrypt(enc)

    aes_ = AES.new(key, AES.MODE_CBC, iv=iv)
    decr_ = aes_.decrypt(enc_)

    assert decr == decr_
    print(f"Decrypted: {unpad(decr,16)}")
