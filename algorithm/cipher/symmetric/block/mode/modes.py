from Crypto.Cipher import AES

for a in (dir(AES)):
    if 'MODE' in a: 
        print(f'AES.new(key, {a})')
