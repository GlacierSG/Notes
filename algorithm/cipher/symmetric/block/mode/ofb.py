def xor(x:bytes, y:bytes): 
    return bytes([x_^y_ for x_,y_ in zip(x,y)])

class OFB:
    def __init__(self, block, key: bytes, iv: bytes):
        self.block = block # .encrypt(), .decrypt()
        self.block_size = block.block_size
        self.iv = iv 

    def encrypt(self, msg: bytes):
        tmp = self.iv
        enc = b''
        for i in range(0,len(msg), self.block_size):
            enc_tmp = self.block.encrypt(tmp)
            enc += xor(enc_tmp, msg[i:i+self.block_size])
            tmp = enc_tmp
        return enc

    def decrypt(self, enc: bytes):
        tmp = self.iv
        msg = b''
        for i in range(0,len(enc), self.block_size):
            enc_tmp = self.block.encrypt(tmp)
            msg += xor(enc_tmp, enc[i:i+self.block_size])
            tmp = enc_tmp
        return msg

if __name__ == '__main__':
    from Crypto.Cipher import AES
    import os
    key = os.urandom(16) # generate 16 byte key
    iv = os.urandom(16) # generate 16 byte iv
    msg = b'This is the message that will be encrypted'

    aes = OFB(AES.new(key, AES.MODE_ECB), key, iv)

    ### Encryption ###
    enc = aes.encrypt(msg)


    ### Decryption ###
    decr = aes.decrypt(enc)

    print(f"Decrypted: {decr}")
