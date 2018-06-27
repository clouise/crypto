#!/Users/carmen/miniconda3/bin/python3
from cryptoutils import *

# Challenge 1
c = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
c = bytes.fromhex(c)

assert (str(b64encode(c), 'utf-8')) == "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"

# Challenge 2
s1 = "1c0111001f010100061a024b53535009181c"
s2 = "686974207468652062756c6c277320657965"

s1 = bytes.fromhex(s1)
s2 = bytes.fromhex(s2)

b = xor(s1, s2)

assert b.hex() == "746865206b696420646f6e277420706c6179"

# Challenge 3
c3 = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
c3 = bytes.fromhex(c3)

print(single_byte_decrypt(c3))

# Challenge 4
text_file = '/Users/carmen/dev/crypto3/files/4.txt'
print(single_byte_decrypt_file(text_file))

# Challenge 5
c5 = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
c5 = bytes(c5, 'utf-8')
key = bytes("ICE", 'utf-8')

byte_encrypted = xor(c5, key)

assert byte_encrypted.hex() == "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"

# Challenge 6
c6 = read_base64_file('/Users/carmen/dev/crypto3/files/6.txt')

for i in guess_keysize(c6)[0:3]:
    key = ""
    for j in transpose_blocks(c6, i[0]):
        key += (single_byte_decrypt(j)[0])
    print(key)

# Challenge 7
c7 = read_base64_file('/Users/carmen/dev/crypto3/files/7.txt')
key = "YELLOW SUBMARINE"
key = bytes(key, 'utf-8')
decrypt = decrypt_ecb(c7, key)
print(decrypt)

# Challenge 8
with open('/Users/carmen/dev/crypto3/files/8.txt', 'r') as f:
    for line in f:
        line = line.strip()
        detect_ecb(line, 16)

