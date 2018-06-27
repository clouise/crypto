#!/Users/carmen/miniconda3/bin/python3
from cryptoutils import *
import pdb

# Challenge 9
c9 = "YELLOW SUBMARI"
c9 = bytes(c9, 'utf-8')
print(pad_pkcs7(c9, 16))

# Challenge 10
c10 = read_base64_file('/Users/carmen/dev/crypto3/files/10.txt')
key = "YELLOW SUBMARINE"
key = bytes(key, 'utf-8')
iv = bytes([0]*16)
plaintext = decrypt_cbc(c10, key, iv)

# Challenge 11
plaintext = "YELLOW SUBMARINEYELLOW SUBMARINEYELLOW SUBMARINEYELLOW SUBMARINE"
plaintext = bytes(plaintext, 'utf-8')
key = "YELLOW SUBMARINE"
key = bytes(key, 'utf-8')
iv = bytes([0]*16)

print(detect_ecb(encryption_chooser(plaintext, key), 16))

# Challenge 12
length = len(encryption_oracle(bytes(), key))

print(break_ecb(length))

# Challenge 13
