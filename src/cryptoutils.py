#!/Users/carmen/miniconda3/bin/python3
from base64 import b64encode
from base64 import b64decode
from Crypto.Cipher import AES


LETTER_FREQUENCIES = {
    'a': 0.0651738,
    'b': 0.0124248,
    'c': 0.0217339,
    'd': 0.0349835,
    'e': 0.1041442,
    'f': 0.0197881,
    'g': 0.0158610,
    'h': 0.0492888,
    'i': 0.0558094,
    'j': 0.0009033,
    'k': 0.0050529,
    'l': 0.0331490,
    'm': 0.0202124,
    'n': 0.0564513,
    'o': 0.0596302,
    'p': 0.0137645,
    'q': 0.0008606,
    'r': 0.0497563,
    's': 0.0515760,
    't': 0.0729357,
    'u': 0.0225134,
    'v': 0.0082903,
    'w': 0.0171272,
    'x': 0.0013692,
    'y': 0.0145984,
    'z': 0.0007836,
    ' ': 0.1918182
}


def xor(string1, string2):
    b = bytearray(len(string1))
    for i in range(len(string1)):
        b[i] = string1[i] ^ string2[i % len(string2)]
    return b


def single_byte_decrypt(cipher):
    max_score = 0
    key = ""
    plaintext = ""
    decodes = []
    for j in range(0,255):
        text = xor(cipher, [j])
        if max_score < score_it(text):
            max_score = score_it(text)
            key = chr(j)
            plaintext = text
    return key, max_score, plaintext


def score_it(string):
    score = 0
    for i in string:
        i = chr(i).lower()
        if i in LETTER_FREQUENCIES:
            score += LETTER_FREQUENCIES[i]
    return score


def single_byte_decrypt_file(text_file):
    with open(text_file, 'r') as f:
        outputs = []
        for line in f:
            s = line.strip()
            s = bytearray.fromhex(s)
            outputs.append(single_byte_decrypt(s))
        f.close()
    return max(outputs, key = lambda x : x[1])


def hamming(string1, string2):
    bits_diff = 0
    for i, j in zip(string1, string2):
        bits_diff += bin(i ^ j).count("1")
    return bits_diff


def guess_keysize(barray):
    keysize = []
    for i in range(2,32):
        b1 = barray[:i]
        b2 = barray[i:i*2]
        b3 = barray[i*2:i*3]
        b4 = barray[i*3:i*4]
        b5 = barray[i*4:i*5]
        d = (hamming(b1, b2) + hamming(b1, b3) + hamming(b1,b4) + hamming(b1, b5)) / (i*5)
        keysize.append([i, d])
    return sorted(keysize, key = lambda x: x[1])[0:3]


def chunks(l, n):
    n = max(1, n)
    return (l[i:i+n] for i in range(0, len(l), n))


def transpose_blocks(barray, keysize):
    blocks = [s for s in chunks(barray, keysize)]
    tblocks = []
    s = []
    for i in range(keysize):
        for block in blocks:
            try:
                s.append(block[i])
            except:
                pass
        tblocks.append(bytes(s))
        s = []
    return tblocks


def read_base64_file(file_path):
    with open(file_path, 'r') as f:
        text = ""
        for line in f:
            text += (line.strip())
    f.close()
    b64 = b64decode(text.encode('utf-8'))
    return b64


def decrypt_ecb(barray, key):
    aes = AES.new(key, AES.MODE_ECB)
    return bytearray(aes.decrypt(barray))


def encrypt_ecb(barray, key):
    aes = AES.new(key, AES.MODE_ECB)
    return bytearray(aes.encrypt(barray))


def encrypt_cbc(plaintext, key, IV):
    plaintext = pad_pkcs7(plaintext, len(key))
    ciphertext = bytearray(len(plaintext))
    prev_block = IV
    for block in chunks(plaintext, len(key)):
        xored = xor(block, prev_block)
        encrypt = encrypt_ecb(xored, key)
        prev_block = xored
        ciphertext.append(encrypt)
    return ciphertext


def decrypt_cbc(ciphertext, key, IV):
    plaintext = bytearray()
    prev_block = IV
    for block in chunks(ciphertext, len(key)):
        decrypt = decrypt_ecb(block, str(key, 'utf-8'))
        xored = xor(decrypt, prev_block)
        prev_block = block
        decrypt = (bytes(xored))
        plaintext.extend(xored)
    return plaintext

def detect_ecb(barray, keysize):
    blocks = list(chunks(barray, keysize))
    for i in blocks:
        if blocks.count(i) > 1:
            print("ECB Detected")


def pad_pkcs7(barray, blocksize):
    diff = (blocksize - len(barray)) % blocksize
    pad = bytearray([diff] * diff)
    return barray + pad
