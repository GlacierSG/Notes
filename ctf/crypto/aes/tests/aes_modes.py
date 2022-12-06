from Crypto.Cipher import AES
a = 'AES.MODE_ECB, AES.MODE_CBC, AES.MODE_CFB, AES.MODE_EAX, AES.MODE_GCM, AES.MODE_OFB, AES.MODE_SIV, AES.MODE_CCM, AES.MODE_CTR, AES.MODE_OCB, AES.MODE_OPENPGP'
for b in a.split(', '):
    print(f'AES.new(key, {b})')
