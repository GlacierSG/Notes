def xor(x:bytes, y:bytes): 
    return bytes([x_^y_ for x_,y_ in zip(x,y)])

class OFB:
    def __init__(self, cipher, iv: bytes):
        self.cipher = cipher # .encrypt(), .decrypt()
        self.block_size = cipher.block_size
        self.iv = iv 

    def encrypt(self, msg: bytes):
        state = self.iv
        enc = b''
        for i in range(0,len(msg), self.block_size):
            enc_state = self.cipher.encrypt(state)
            enc += xor(enc_state, msg[i:i+self.block_size])
            state = enc_state
        return enc

    def decrypt(self, enc: bytes):
        state = self.iv
        msg = b''
        for i in range(0,len(enc), self.block_size):
            enc_state = self.cipher.encrypt(state)
            msg += xor(enc_state, enc[i:i+self.block_size])
            state = enc_state
        return msg

if __name__ == '__main__':
    from Crypto.Cipher import AES
    import os
    key = os.urandom(16) # generate 16 byte key
    iv = os.urandom(16) # generate 16 byte iv
    msg = b'This is the message that will be encrypted'

    aes = OFB(AES.new(key, AES.MODE_ECB), iv)

    ### Encryption ###
    enc = aes.encrypt(msg)


    ### Decryption ###
    decr = aes.decrypt(enc)

    print(f"Decrypted: {decr}")
