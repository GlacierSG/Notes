from Crypto.Cipher import AES

from Crypto.Util.strxor import strxor as xor
class AES_CFB:
    def __init__(self, key: bytes, iv: bytes):
        self.aes = AES.new(key, AES.MODE_ECB)
        self.iv = iv # 16 byte iv

    def encrypt(self, msg: bytes):
        enc = self.iv
        for i in range(0,len(msg),16):
            blk_xor_prevenc = xor(enc[i:i+16], msg[i:i+16])
            enc += self.aes.encrypt(blk_xor_prevenc)
        return enc[16:]

    def decrypt(self, enc: bytes):
        enc = self.iv + enc
        msg = b''
        for i in range(16,len(enc),16):
            blk_xor_prevenc = self.aes.decrypt(enc[i:i+16])
            msg += xor(enc[i-16:i], blk_xor_prevenc)
        return msg


if __name__ == '__main__':
    from aes_pad import pad, unpad
    import os
    key = os.urandom(16) # generate 16 byte key
    iv = os.urandom(16) # generate 16 byte iv
    msg = b'This is the messaege that will be encrypted'

    aes = AES_CFB(key, iv)

    ### Encryption ###
    enc = aes.encrypt(msg)

    aes_ = AES.new(key, AES.MODE_CFB, iv=iv)
    enc_ = aes_.encrypt(msg)

    assert enc_ == enc

    ### Decryption ###
    decr = aes.decrypt(enc)

    aes_ = AES.new(key, AES.MODE_CFB, iv=iv)
    decr_ = aes_.decrypt(enc_)

    assert decr == decr_
