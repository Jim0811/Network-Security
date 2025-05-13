############################ for test ##############################
# import random
# import string

# def generate_key(length):
#     # 定義字元範圍 0-9 + a-z
#     characters = string.digits + string.ascii_lowercase
#     # 隨機抽取 length 個字元組成金匙
#     key = ''.join(random.choice(characters) for _ in range(length))
#     return key

# # 範例：產生長度 10 的金匙
# key = generate_key(5)
# print("隨機金匙：", key)

import random

# ECC 曲線參數（簡單示範用，正式用應該要挑安全的 p, a, b）
p = 2**256 - 2**32 - 2**9 - 2**8 - 2**7 - 2**6 - 2**4 - 1  
a = 0
b = 7
G = (0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798, 
     0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8)

def point_add(P, Q):
    if P == (None, None): return Q
    if Q == (None, None): return P
    if P == Q:
        lmb = (3 * P[0] ** 2 + a) * pow(2 * P[1], p-2, p) % p
    else:
        if P[0] == Q[0]:
            return (None, None)
        lmb = (Q[1] - P[1]) * pow(Q[0] - P[0], p-2, p) % p

    xr = (lmb**2 - P[0] - Q[0]) % p
    yr = (lmb * (P[0] - xr) - P[1]) % p
    return (xr, yr)

def generate_seeds(key):
    base_seed = 0
    for c in key:
        base_seed = (base_seed * 131 + ord(c)) % (10**9+7)
    return base_seed

def pad_text(text, size):
    charset = '0123456789abcdefghijklmnopqrstuvwxyz'
    random.seed(len(text))
    while len(text) < size:
        text += random.choice(charset)
    return text

def to_3d_matrix(text, size):
    matrix = [[[None for _ in range(size)] for _ in range(size)] for _ in range(size)]
    idx = 0
    for i in range(size):
        for j in range(size):
            for k in range(size):
                matrix[i][j][k] = text[idx]
                idx += 1
    return matrix

def flatten_3d(matrix):
    return ''.join(matrix[i][j][k] for i in range(len(matrix))
                                      for j in range(len(matrix[0]))
                                      for k in range(len(matrix[0][0])))

def encrypt(plaintext, key):
    base_seed = generate_seeds(key)
    length = len(plaintext)
    size = 9
    total_size = size ** 3
    plaintext_padded = pad_text(plaintext, total_size)
    matrix = to_3d_matrix(plaintext_padded, size)

    coords = [(i, j, k) for i in range(size) for j in range(size) for k in range(size)]
    flat_cipher = [''] * total_size

    # 初始點 = (base_seed mod p, base_seed mod p)
    seed_point = (base_seed % p, base_seed % p)

    idx = 0
    while coords:
        # 每次取 seed_point.x mod 剩餘座標數
        pos_idx = seed_point[0] % len(coords)
        pos = coords.pop(pos_idx)

        i, j, k = pos
        flat_cipher[idx] = matrix[i][j][k]

        # 更新 seed_point = seed_point + G
        seed_point = point_add(seed_point, G)

        idx += 1

    length_str = str(length).zfill(4)
    return ''.join(flat_cipher) + length_str, base_seed, size

def decrypt(ciphertext, key, base_seed, size):
    total_size = size ** 3
    cipher_body = ciphertext[:-4]
    original_length = int(ciphertext[-4:])

    matrix = [[[None for _ in range(size)] for _ in range(size)] for _ in range(size)]
    coords = [(i, j, k) for i in range(size) for j in range(size) for k in range(size)]

    seed_point = (base_seed % p, base_seed % p)

    idx = 0
    while coords:
        pos_idx = seed_point[0] % len(coords)
        pos = coords.pop(pos_idx)

        i, j, k = pos
        matrix[i][j][k] = cipher_body[idx]

        seed_point = point_add(seed_point, G)

        idx += 1

    return flatten_3d(matrix)[:original_length]

# 範例
plaintext = "HELLO"
key = "KEY"

ciphertext, base_seed, size = encrypt(plaintext, key)
print("明文：", plaintext)
print("密文：", ciphertext)

decrypted = decrypt(ciphertext, key, base_seed, size)
print("解密：", decrypted)