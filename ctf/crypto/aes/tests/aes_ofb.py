from Crypto.Cipher import AES

def xor(x:bytes, y:bytes): 
    return bytes([x_^y_ for x_,y_ in zip(x,y)])

class AES_OFB:
    def __init__(self, key: bytes, iv: bytes):
        self.aes = AES.new(key, AES.MODE_ECB)
        self.iv = iv # 16 byte iv

    def encrypt(self, msg: bytes):
        tmp = self.iv
        enc = b''
        for i in range(0,len(msg), 16):
            enc_tmp = self.aes.encrypt(tmp)
            enc += xor(enc_tmp, msg[i:i+16])
            tmp = enc_tmp
        return enc

    def decrypt(self, enc: bytes):
        tmp = self.iv
        msg = b''
        for i in range(0,len(enc), 16):
            enc_tmp = self.aes.encrypt(tmp)
            msg += xor(enc_tmp, enc[i:i+16])
            tmp = enc_tmp
        return msg

if __name__ == '__main__':
    from aes_pad import pad, unpad
    import os
    key = os.urandom(16) # generate 16 byte key
    iv = os.urandom(16) # generate 16 byte iv
    msg = b'This is the message that will be encrypted'

    aes = AES_OFB(key, iv)

    ### Encryption ###
    enc = aes.encrypt(msg)

    aes_ = AES.new(key, AES.MODE_OFB, iv=iv)
    enc_ = aes_.encrypt(msg)

    assert enc_ == enc, f'{enc = }, {enc_ = }'

    ### Decryption ###
    decr = aes.decrypt(enc)

    aes_ = AES.new(key, AES.MODE_OFB, iv=iv)
    decr_ = aes_.decrypt(enc_)

    assert decr == decr_, f'{decr = }, {decr_ = }'
