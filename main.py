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
import math

def generate_seeds(key):
    base_seed = 0
    for c in key:
        base_seed = (base_seed * 131 + ord(c)) % (10**9+7)
    return base_seed

def pad_text(text, size):
    charset = '0123456789abcdefghijklmnopqrstuvwxyz'
    random.seed(len(text))  # 確保固定填充序列
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
    random.seed(base_seed)

    length = len(plaintext)
    size = 9
    total_size = size ** 3
    plaintext_padded = pad_text(plaintext, total_size)
    matrix = to_3d_matrix(plaintext_padded, size)

    coords = [(i, j, k) for i in range(size) for j in range(size) for k in range(size)]
    flat_cipher = [''] * total_size

    idx = 0
    dynamic_seed = base_seed

    while coords:
        random.seed(dynamic_seed)
        pos = random.choice(coords)
        coords.remove(pos)

        i, j, k = pos
        flat_cipher[idx] = matrix[i][j][k]

        char_val = ord(matrix[i][j][k])
        dynamic_seed = (dynamic_seed * 131 + char_val + idx * 17) % (10**9+7)

        idx += 1

    # 密文最後附上原長度（用固定4碼十進位）
    length_str = str(length).zfill(4)
    return ''.join(flat_cipher) + length_str, base_seed, size

def decrypt(ciphertext, key, base_seed, size):
    random.seed(base_seed)

    total_size = size ** 3
    cipher_body = ciphertext[:-4]
    original_length = int(ciphertext[-4:])

    matrix = [[[None for _ in range(size)] for _ in range(size)] for _ in range(size)]
    coords = [(i, j, k) for i in range(size) for j in range(size) for k in range(size)]

    idx = 0
    dynamic_seed = base_seed

    while coords:
        random.seed(dynamic_seed)
        pos = random.choice(coords)
        coords.remove(pos)

        i, j, k = pos
        matrix[i][j][k] = cipher_body[idx]

        char_val = ord(cipher_body[idx])
        dynamic_seed = (dynamic_seed * 131 + char_val + idx * 17) % (10**9+7)

        idx += 1

    return flatten_3d(matrix)[:original_length]

# 範例
plaintext = "hello678890hjl"
key = "k3z78"

ciphertext, base_seed, size = encrypt(plaintext, key)
print("明文：", plaintext)
print("密文：", ciphertext)

decrypted = decrypt(ciphertext, key, base_seed, size)
print("解密：", decrypted)

