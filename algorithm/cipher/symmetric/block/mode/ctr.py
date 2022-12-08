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

if __name__ == '__main__':
    from Crypto.Cipher import AES
    import os
    key = os.urandom(16) 
    nonce = os.urandom(8) 
    msg = b'This is the message that will be encrypted'

    aes = CTR(AES.new(key, AES.MODE_ECB), key, nonce)

    ### Encryption ###
    enc = aes.encrypt(msg)


    ### Decryption ###
    decr = aes.decrypt(enc)

    print(f"Decrypted: {decr}")
