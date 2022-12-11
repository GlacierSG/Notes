# Cipher Block Mode Attacks

## Basic implementations

### Padding Attack (PA)

### Chosen Plaintext Attack (CPA)

```python
import logging

def encrypt(msg: bytes) -> bytes: pass
def cpa(encrypt: type(encrypt),
        block_size=16,
        prefix_len=0,
        suffix=b'',
        rounds=100,
        alphabet=bytes(range(256))):

    def getBlock(data, nr):
        return data[nr*block_size:][:block_size]

    for r in range(rounds):
        fill = (15 - prefix_len - len(suffix)) % block_size
        real = encrypt(b'0'*fill)
        blk_nr = (prefix_len + fill + len(suffix)) // block_size
        for c in alphabet:
            c = bytes([c])
            test = encrypt(b'0'*fill + suffix + c)
            if getBlock(real,blk_nr) == getBlock(test,blk_nr):
                suffix += c
                logging.info(f'{suffix = }')
                break
    return suffix
```

### Chosen Ci (CCA)
