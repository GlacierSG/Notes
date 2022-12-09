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

if __name__ == '__main__':
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
    import os

    key = os.urandom(16) # generate 16 byte key
    msg = pad(b'This is the message that will be encrypted', 16)

    aes = ECB(AES.new(key, AES.MODE_ECB))

    ### Encryption ###
    enc = aes.encrypt(msg)

    ### Decryption ###
    decr = aes.decrypt(enc)

    print(f"Decrypted: {unpad(decr, 16)}")
