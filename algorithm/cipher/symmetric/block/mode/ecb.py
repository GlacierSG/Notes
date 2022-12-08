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

if __name__ == '__main__':
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
    import os

    key = os.urandom(16) # generate 16 byte key
    msg = pad(b'This is the message that will be encrypted', 16)

    aes = ECB(AES.new(key, AES.MODE_ECB), key)

    ### Encryption ###
    enc = aes.encrypt(msg)

    ### Decryption ###
    decr = aes.decrypt(enc)

    print(f"Decrypted: {unpad(decr, 16)}")
