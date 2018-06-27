#!/Users/carmen/miniconda3/bin/python3
from cryptoutils import *

# Challenge 9
c9 = "YELLOW SUBMARI"
c9 = bytearray(c9, 'utf-8')
print(pad_pkcs7(c9, 16))

# Challenge 10
c10 = read_base64_file('/Users/carmen/dev/crypto3/files/10.txt')
key = "YELLOW SUBMARINE"
key = bytearray(key, 'utf-8')
iv = bytearray([0]*16)
plaintext = decrypt_cbc(c10, key, iv)
print(str(plaintext))
