from Crypto.Cipher import AES
class AES_ECB:
    def __init__(self, key: bytes):
        self.aes = AES.new(key, AES.MODE_ECB)

    def encrypt(self, msg: bytes):
        enc = b''
        for i in range(0,len(msg),16):
            enc += self.aes.encrypt(msg[i:i+16])
        return enc

    def decrypt(self, enc: bytes):
        msg = b''
        for i in range(0,len(enc),16):
            msg += self.aes.decrypt(enc[i:i+16])
        return msg

if __name__ == '__main__':
    from aes_pad import pad, unpad
    import os

    key = os.urandom(16) # generate 16 byte key
    msg = pad(b'This is the message that will be encrypted')

    aes = AES_ECB(key)

    ### Encryption ###
    enc = aes.encrypt(msg)

    aes_ = AES.new(key, AES.MODE_ECB)
    enc_ = aes_.encrypt(msg)
    assert enc_ == enc

    ### Decryption ###
    decr = aes.decrypt(enc)

    aes_ = AES.new(key, AES.MODE_ECB)
    decr_ = aes_.decrypt(enc_)
    assert decr == decr_
    print(f"Decrypted: {unpad(decr)}")
