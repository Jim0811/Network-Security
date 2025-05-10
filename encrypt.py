import random
from Crypto.PublicKey import RSA 
from Crypto.Cipher import PKCS1_OAEP 

# 原本的種子產生函數
def generate_seeds(key):
    base_seed = 0
    for c in key:
        base_seed = (base_seed * 131 + ord(c)) % (10**9 + 7)
    return base_seed

# 字元填充
def pad_text(text, size):
    charset = '0123456789abcdefghijklmnopqrstuvwxyz'
    random.seed(len(text))
    while len(text) < size:
        text += random.choice(charset)
    return text

# 轉換為 3D 矩陣
def to_3d_matrix(text, size):
    matrix = [[[None for _ in range(size)] for _ in range(size)] for _ in range(size)]
    idx = 0
    for i in range(size):
        for j in range(size):
            for k in range(size):
                matrix[i][j][k] = text[idx]
                idx += 1
    return matrix

# 平鋪 3D 矩陣
def flatten_3d(matrix):
    return ''.join(matrix[i][j][k] for i in range(len(matrix))
                                      for j in range(len(matrix[0]))
                                      for k in range(len(matrix[0][0])))

# 多表代換表生成
def generate_multiple_sub_tables(key, num_tables):
    base_seed = generate_seeds(key)
    charset = list('0123456789abcdefghijklmnopqrstuvwxyz')
    tables = []

    for i in range(num_tables):
        random.seed(base_seed + i * 9973)
        shuffled = charset[:]
        random.shuffle(shuffled)
        enc_table = dict(zip(charset, shuffled))
        dec_table = dict(zip(shuffled, charset))
        tables.append((enc_table, dec_table))

    return tables

# 整合加密：換位 → 多表代換
def encrypt(plaintext, key, block_size=10):
    base_seed = generate_seeds(key)
    random.seed(base_seed)

    size = 9
    total_size = size ** 3
    padded = pad_text(plaintext, total_size)
    matrix = to_3d_matrix(padded, size)

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
        dynamic_seed = (dynamic_seed * 131 + char_val + idx * 17) % (10**9 + 7)

        idx += 1

    # 多表代換（每 block_size 字元換一張表）
    tables = generate_multiple_sub_tables(key, (total_size // block_size) + 1)
    final_cipher = []
    for i, c in enumerate(flat_cipher):
        table_id = i // block_size
        enc_table, _ = tables[table_id]
        final_cipher.append(enc_table.get(c, c))  # 不在 charset 中的直接保留

    length_str = str(len(plaintext)).zfill(4)
    return ''.join(final_cipher) + length_str, base_seed, size

plaintext = "se245d3c"
key = "34AZY"

# read public key
with open("de_public.pem", "rb") as f:
    de_public_key = RSA.import_key(f.read())

cipher = PKCS1_OAEP.new(de_public_key)
encrypted_message = cipher.encrypt(key.encode())

with open("key.bin", "wb") as f:
    f.write(encrypted_message)

ciphertext, seed, size = encrypt(plaintext, key)
print("明文：", plaintext)
print("密文：", ciphertext)