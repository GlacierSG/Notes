# RSA (Rivest–Shamir–Adleman)

RSA is a public/private key encryption system

## Using

- [python3](https://www.python.org)
	- [pycryptodome](https://www.pycryptodome.org/)

## Basic Implementation

```python
from Crypto.Util.number import getPrime
from math import gcd

def gen_rsa_keys(e, primes_bit_len):
    while True:
        p = getPrime(primes_bit_len)
        q = getPrime(primes_bit_len)

        # make sure pow(d, -1, phi) can be computed
        if gcd(p-1, e) == 1 and gcd(q-1, e):
            break
    return p, q
```
### RSA Implementation
```python
class RSA:
    def __init__(self, e=0x10001, bit_len=1024):
        p, q = gen_rsa_keys(e, bit_len)
        n = p*q
        phi = (p-1)*(q-1)
        d = pow(e, -1, phi)

        self.pub  = (n, e) # public key
        self.priv = (d) # private key

    def encrypt(self, msg: int):
        n, e = self.pub
        assert 0 <= msg < n
        return pow(msg, e, n)

    def decrypt(self, enc: int):
        n, e = self.pub
        d = self.priv
        return pow(enc, d, n)
```

### RSA-CRT Implementation

The implementation commonly seen on places like [wikipedia](https://en.wikipedia.org/wiki/RSA_(cryptosystem)#Using_the_Chinese_remainder_algorithm) uses a special case of the CRT (Chinese Remainder Theorem) algorithm in order to get more speedups

```python
class RSA:
    def __init__(self, e=0x10001, bit_len=1024):
        p, q = gen_rsa_keys(e, bit_len)
        n = p*q
        phi = (p-1)*(q-1)
        d = pow(e, -1, phi)
        dp = d % (p-1)
        dq = d % (q-1)

        self.pub  = (n, e) # public key
        self.priv = (p, q, dp, dq) # private key

    def encrypt(self, msg: int):
        n, e = self.pub
        assert 0 <= msg < n

        return pow(msg, e, n)

    def decrypt(self, enc: int):
        n, _ = self.pub
        p, q, dp, dq = self.priv
        qinv = pow(q, -1, p)

        mp = pow(enc, dp, n)
        mq = pow(enc, dq, n)
        # CRT special case
        h = (qinv * (mp - mq)) % p 
        return (mq + h*q) % n
```

## Attacks

