sbox = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)

inverse_sbox = (
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
)

rcon = (
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
    0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A,
    0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A,
    0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39,
)


def subBytes(block):
    for i in range(4):
        for j in range(4):
            block[i][j] = sbox[block[i][j]]

def inverse_subBytes(block):
    for i in range(4):
        for j in range(4):
            block[i][j] = inverse_sbox[block[i][j]]


def shiftRows(block):
    block[0][1], block[1][1], block[2][1], block[3][1] = block[1][1], block[2][1], block[3][1], block[0][1]
    block[0][2], block[1][2], block[2][2], block[3][2] = block[2][2], block[3][2], block[0][2], block[1][2]
    block[0][3], block[1][3], block[2][3], block[3][3] = block[3][3], block[0][3], block[1][3], block[2][3]

def inverse_shiftRows(block):
    block[0][1], block[1][1], block[2][1], block[3][1] = block[3][1], block[0][1], block[1][1], block[2][1]
    block[0][2], block[1][2], block[2][2], block[3][2] = block[2][2], block[3][2], block[0][2], block[1][2]
    block[0][3], block[1][3], block[2][3], block[3][3] = block[1][3], block[2][3], block[3][3], block[0][3]


def addRoundKey(block, key):
    for i in range(4):
        for j in range(4):
            block[i][j] ^= key[i][j]


galois = lambda a: (((a << 1) ^ 0x1B) & 0xFF) if (a & 0x80) else (a << 1)

def mixSingleColumn(column):
    t = column[0] ^ column[1] ^ column[2] ^ column[3]
    temp = column[0]
    column[0] ^= t ^ galois(column[0] ^ column[1])
    column[1] ^= t ^ galois(column[1] ^ column[2])
    column[2] ^= t ^ galois(column[2] ^ column[3])
    column[3] ^= t ^ galois(column[3] ^ temp)

def mixColumns(block):
    for i in range(4):
        mixSingleColumn(block[i])

def inverse_mixColumns(block):
    for i in range(4):
        u = galois(galois(block[i][0] ^ block[i][2]))
        v = galois(galois(block[i][1] ^ block[i][3]))
        block[i][0] ^= u
        block[i][1] ^= v
        block[i][2] ^= u
        block[i][3] ^= v

    mixColumns(block)


def bytesToMatrix(text):
    return [list(text[i:i+4]) for i in range(0, len(text), 4)]

def matrixToBytes(matrix):
    return bytes(sum(matrix, []))

def xorBytes(a, b):
    return bytes(i^j for i, j in zip(a, b))

def pad(plaintext):
    padding_length = 16 - (len(plaintext) % 16)
    padding = bytes([padding_length] * padding_length)
    return plaintext + padding

def unpad(plaintext):
    padding_length = plaintext[-1]
    message, padding = plaintext[:-padding_length], plaintext[-padding_length:]
    return message

def split_blocks(message, block_size=16, require_padding=True):
    return [message[i:i+16] for i in range(0, len(message), block_size)]


class AES:
    roundsForKeySize = {16: 10, 24: 12, 32: 14}

    def __init__(self, encryption_key):
        self.roundNumber = AES.roundsForKeySize[len(encryption_key)]
        self.expandedKey = self.expandKey(encryption_key)

    def expandKey(self, encryption_key):
        key_columns = bytesToMatrix(encryption_key)
        iteration_size = len(encryption_key) // 4

        i = 1
        while len(key_columns) < (self.roundNumber + 1) * 4:
            word = list(key_columns[-1])

            if len(key_columns) % iteration_size == 0:
                word.append(word.pop(0))
                word = [sbox[b] for b in word]
                word[0] ^= rcon[i]
                i += 1
            elif len(encryption_key) == 32 and len(key_columns) % iteration_size == 4:
                word = [sbox[b] for b in word]

            word = xorBytes(word, key_columns[-iteration_size])
            key_columns.append(word)

        return [key_columns[4*i : 4*(i+1)] for i in range(len(key_columns) // 4)]

    def encrypt_block(self, plaintext):
        plain_state = bytesToMatrix(plaintext)

        addRoundKey(plain_state, self.expandedKey[0])

        for i in range(1, self.roundNumber):
            subBytes(plain_state)
            shiftRows(plain_state)
            mixColumns(plain_state)
            addRoundKey(plain_state, self.expandedKey[i])

        subBytes(plain_state)
        shiftRows(plain_state)
        addRoundKey(plain_state, self.expandedKey[-1])

        return matrixToBytes(plain_state)

    def decrypt_block(self, ciphertext):
        cipher_state = bytesToMatrix(ciphertext)

        addRoundKey(cipher_state, self.expandedKey[-1])
        inverse_shiftRows(cipher_state)
        inverse_subBytes(cipher_state)

        for i in range(self.roundNumber - 1, 0, -1):
            addRoundKey(cipher_state, self.expandedKey[i])
            inverse_mixColumns(cipher_state)
            inverse_shiftRows(cipher_state)
            inverse_subBytes(cipher_state)

        addRoundKey(cipher_state, self.expandedKey[0])

        return matrixToBytes(cipher_state)

    def encrypt_cbc(self, plaintext, iv):
        plaintext = pad(plaintext)

        blocks = []
        previous = iv
        for plaintext_block in split_blocks(plaintext):
            block = self.encrypt_block(xorBytes(plaintext_block, previous))
            blocks.append(block)
            previous = block

        return b''.join(blocks)

    def decrypt_cbc(self, ciphertext, iv):
        blocks = []
        previous = iv
        for ciphertext_block in split_blocks(ciphertext):
            blocks.append(xorBytes(previous, self.decrypt_block(ciphertext_block)))
            previous = ciphertext_block

        return unpad(b''.join(blocks))


import os
from hashlib import pbkdf2_hmac

AES_KEY_SIZE = 16
IV_SIZE = 16
SALT_SIZE = 16


def get_key_iv(password, salt, workload=100000):
    stretched = pbkdf2_hmac('sha256', password, salt, workload)
    aes_key, stretched = stretched[:AES_KEY_SIZE], stretched[AES_KEY_SIZE:]
    iv = stretched[:IV_SIZE]
    return aes_key, iv


def encrypt(key, plaintext, workload=100000):
    if isinstance(key, str):
        key = key.encode('utf-8')
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')

    salt = os.urandom(SALT_SIZE)
    key, iv = get_key_iv(key, salt, workload)
    ciphertext = AES(key).encrypt_cbc(plaintext, iv)

    return salt + ciphertext


def decrypt(key, ciphertext, workload=100000):
    if isinstance(key, str):
        key = key.encode('utf-8')

    salt, ciphertext = ciphertext[:SALT_SIZE], ciphertext[SALT_SIZE:]
    key, iv = get_key_iv(key, salt, workload)

    return AES(key).decrypt_cbc(ciphertext, iv)


def encryptTextFile(filename, key):
    fileInput = open(filename, "r")
    fileContent = fileInput.read()
    encryptedText = encrypt(key, fileContent)
    fileInput.close()
    fileOutput = open(filename, "wb")
    fileOutput.write(encryptedText)
    fileOutput.close()

def decryptTextFile(filename, key):
    fileInput = open(filename, "rb")
    fileContent = fileInput.read()
    decryptedText = decrypt(key, fileContent).decode("utf-8")
    fileInput.close()
    fileOutput = open(filename, "w")
    fileOutput.write(decryptedText)
    fileOutput.close()

# encryptTextFile("hello.txt", "myKey")
# decryptTextFile("hello.txt", "myKey")

def encryptImage(filename, key):
    fileInput = open(filename, "rb")
    fileContent = fileInput.read()
    encryptedText = encrypt(key, fileContent)
    fileInput.close()
    fileOutput = open(filename, "wb")
    fileOutput.write(encryptedText)
    fileOutput.close()

def decryptImage(filename, key):
    fileInput = open(filename, "rb")
    fileContent = fileInput.read()
    decryptedText = decrypt(key, fileContent)
    fileInput.close()
    fileOutput = open(filename, "wb")
    fileOutput.write(decryptedText)
    fileOutput.close()

# encryptImage("logo.png", "myKey")
# decryptImage("logo.png", "myKey")