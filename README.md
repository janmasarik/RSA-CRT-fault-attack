# RSA-CRT-fault-attack
Detailed attack described here: https://www.cryptologie.net/article/371/fault-attacks-on-rsas-signatures/

## Conditions required to make use of this script:
- validity of signature isn't checked after computation (big implementation error)
- deterministic (legacy) padding scheme (PKCS #1 v1.5)
- some fault in one of the CRT computations (eg. bit-flip in prime introduced by attacker)
- SHA256 is hardcoded

## Usage
Sign malicious_message.txt using following parameters
```python
python3 ../rsa-crt.py public_key.pem message.txt message_sig.sha256 malicious_message.txt
```

Requires module cryptography (only good python package for crypto). If you don't have it yet, install it with 
```
pip3 install cryptography
```