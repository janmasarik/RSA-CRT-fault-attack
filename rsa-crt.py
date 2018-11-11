import sys
import hashlib
from math import gcd
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key


def validate_signature(message, signature, public_key):
    """Returns True if signature is valid for given message and public key. """
    try:
        public_key.verify(signature, message, padding.PKCS1v15(), hashes.SHA256())
    except InvalidSignature:
        return False

    return True


def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)


def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise ValueError("modular inverse does not exist")
    else:
        return x % m


def load_public_key(filename):
    with open(filename, "rb") as pem_in:
        pemlines = pem_in.read()
    return load_pem_public_key(pemlines, default_backend())


def extract_private_key(public_key, faulty_signature, message):
    """Attempts to extract private key from faulty signature made using CRT with 1 faulty prime."""
    e = public_key.public_numbers().e
    N = public_key.public_numbers().n
    sha256_header = [
        int(i, 16)
        for i in "30 31 30 0D 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20".split()
    ]
    sha256_hash = hashlib.sha256(message)
    F_bytes = [255] * (
        public_key.key_size // 8 - 3 - len(sha256_header) - sha256_hash.digest_size
    )
    padded_message = (
        bytearray([0, 1] + F_bytes + [0] + sha256_header) + sha256_hash.digest()
    )

    p = gcd(
        int.from_bytes(faulty_signature, "big") ** e - int.from_bytes(padded_message, "big"),
        N,
    )

    q = N // p

    d = modinv(e, (p - 1) * (q - 1))

    return rsa.RSAPrivateNumbers(
        p,
        q,
        d,
        rsa.rsa_crt_dmp1(d, p),
        rsa.rsa_crt_dmp1(d, q),
        rsa.rsa_crt_iqmp(p, q),
        rsa.RSAPublicNumbers(e, N),
    ).private_key(default_backend())


if __name__ == "__main__":
    public_key = load_public_key(sys.argv[1])
    message = open(sys.argv[2], "rb").read()
    signature = open(sys.argv[3], "rb").read()

    if validate_signature(message, signature, public_key):
        print("Correct signature")
        exit(1)

    malicious_message = open(sys.argv[4], "rb").read()
    private_key = extract_private_key(public_key, signature, message)

    malicious_signature = private_key.sign(
        malicious_message, padding.PKCS1v15(), hashes.SHA256()
    )

    with open("malicious_sig.sha256", "wb") as f:
        f.write(malicious_signature)
    print("Very very very malicious signature saved to malicious_sig.sha256")
