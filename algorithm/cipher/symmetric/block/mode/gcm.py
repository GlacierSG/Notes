def xor(x:bytes, y:bytes):
    return bytes([x_^y_ for x_,y_ in zip(x,y)])

def ghash(aad, msg):

class GCM:
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


if __name__ == '__main__':
    from Crypto.Cipher import AES
    import os

    key = os.urandom(16) # generate 16 byte key
    iv = os.urandom(16) # generate 16 byte iv
    msg = b'This is the message that will be encrypted'

    aes = CFB(AES.new(key, AES.MODE_ECB), key, iv)

    ### Encryption ###
    enc = aes.encrypt(msg)


    ### Decryption ###
    decr = aes.decrypt(enc)

    print(f"Decrypted: {decr}")
