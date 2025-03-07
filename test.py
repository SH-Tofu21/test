from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Hash import MD5, SHA1
import base64

# Hardcoded RSA key (Security Risk)
private_key = RSA.generate(2048)
public_key = private_key.publickey()

# AES Encryption
def encrypt_aes(data, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return base64.b64encode(cipher.encrypt(data.ljust(16)))

# MD5 Hashing (Weak)
def hash_md5(data):
    return MD5.new(data.encode()).hexdigest()

# SHA-1 Hashing (Weak)
def hash_sha1(data):
    return SHA1.new(data.encode()).hexdigest()

print("AES:", encrypt_aes("test", b"1234567890abcdef"))
print("MD5:", hash_md5("test"))
print("SHA-1:", hash_sha1("test"))
