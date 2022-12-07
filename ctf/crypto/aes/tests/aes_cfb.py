from Crypto.Cipher import AES

class AES_CFB:
    def __init__(self, key: bytes, iv: bytes):
        self.aes = AES.new(key, AES.MODE_ECB)
        self.iv = iv # 16 byte iv

    def encrypt(self, msg: bytes):
        tmp = self.iv
        enc = b''
        for i in range(0,len(msg)):
            enc_tmp = self.aes.encrypt(tmp)
            enc += bytes([enc_tmp[0] ^ msg[i]])
            tmp = tmp[1:] + bytes([enc[-1]])
        return enc

    def decrypt(self, enc: bytes):
        tmp = self.iv
        msg = b''
        for i in range(0,len(enc)):
            enc_tmp = self.aes.encrypt(tmp)
            msg += bytes([enc_tmp[0] ^ enc[i]])
            tmp = tmp[1:] + bytes([enc[i]])
        return msg 


if __name__ == '__main__':
    from aes_pad import pad, unpad
    import os
    key = os.urandom(16) # generate 16 byte key
    iv = os.urandom(16) # generate 16 byte iv
    msg = b'This is the message that will be encrypted'

    aes = AES_CFB(key, iv)

    ### Encryption ###
    enc = aes.encrypt(msg)

    aes_ = AES.new(key, AES.MODE_CFB, iv=iv)
    enc_ = aes_.encrypt(msg)

    assert enc_ == enc, f'{enc = }, {enc_ = }'

    ### Decryption ###
    decr = aes.decrypt(enc)

    aes_ = AES.new(key, AES.MODE_CFB, iv=iv)
    decr_ = aes_.decrypt(enc_)

    assert decr == decr_, f'{decr = }, {decr_ = }'
