import random
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def generate_seeds(key):
    base_seed = 0
    for c in key:
        base_seed = (base_seed * 131 + ord(c)) % (10**9 + 7)
    return base_seed

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

def decrypt(ciphertext, key, size = 9, block_size=10):
    total_size = size ** 3
    cipher_body = ciphertext[:-4]
    original_length = int(ciphertext[-4:])
    base_seed = generate_seeds(key)
    # 多表解密
    tables = generate_multiple_sub_tables(key, (total_size // block_size) + 1)
    recovered_text = []
    for i, c in enumerate(cipher_body):
        table_id = i // block_size
        _, dec_table = tables[table_id]
        recovered_text.append(dec_table.get(c, c))

    # 換位復原
    matrix = [[[None for _ in range(size)] for _ in range(size)] for _ in range(size)]
    coords = [(i, j, k) for i in range(size) for j in range(size) for k in range(size)]

    idx = 0
    dynamic_seed = base_seed
    while coords:
        random.seed(dynamic_seed)
        pos = random.choice(coords)
        coords.remove(pos)

        i, j, k = pos
        matrix[i][j][k] = recovered_text[idx]

        char_val = ord(recovered_text[idx])
        dynamic_seed = (dynamic_seed * 131 + char_val + idx * 17) % (10**9 + 7)

        idx += 1

    return flatten_3d(matrix)[:original_length]

ciphertext = input("Input the cyphertext：")

#RSA
try:
    with open("de_private.pem", "rb") as f:
        de_private_key = RSA.import_key(f.read())
except FileNotFoundError:
    de_key = RSA.generate(1024)
    with open("de_private.pem", "wb") as f:
        f.write(de_key.export_key())
    with open("de_public.pem", "wb") as f:
        f.write(de_key.publickey().export_key())
    de_private_key = de_key

decipher = PKCS1_OAEP.new(de_private_key)
with open("key.bin", "rb") as f:
    encrypted_message = f.read()

# 解密
key = decipher.decrypt(encrypted_message).decode()
print("key：", key)

decrypted = decrypt(ciphertext, key)
print("解密：", decrypted)