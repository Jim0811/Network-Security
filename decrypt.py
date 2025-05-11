import random
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64

def generate_playfair_key_string(key: str) -> str:
    DEFAULT_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    used_chars = set()
    processed_key = []
    for c in key.upper():
        if c in DEFAULT_CHARS and c not in used_chars:
            processed_key.append(c)
            used_chars.add(c)
    for c in DEFAULT_CHARS:
        if c not in used_chars:
            processed_key.append(c)
    return ''.join(processed_key[:32])

class CustomBase32:
    def __init__(self, alphabet: str):
        if len(alphabet) != 32:
            raise ValueError("Alphabet must be exactly 32 characters")
        self.alphabet = alphabet
        self.char_map = {c: i for i, c in enumerate(alphabet)}
        
    def decode(self, data: str) -> str:
        if not data:
            return ""
        buffer = 0
        bits_left = 0
        output = []
        for c in data:
            if c not in self.char_map:
                if c == '=':
                    continue
                raise ValueError(f"Invalid character '{c}' in Base32 input")
            buffer = (buffer << 5) | self.char_map[c]
            bits_left += 5
            if bits_left >= 8:
                bits_left -= 8
                output.append((buffer >> bits_left) & 0xFF)
        return bytes(output).decode('utf-8', errors='replace')

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
    charset = list('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789')
    tables = []

    for i in range(num_tables):
        random.seed(base_seed + i * 9973)
        shuffled = charset[:]
        random.shuffle(shuffled)
        enc_table = dict(zip(charset, shuffled))
        dec_table = dict(zip(shuffled, charset))
        tables.append((enc_table, dec_table))

    return tables

def decrypt(ciphertext, key, size=9, block_size=10):
    # 1. 首先進行多表代換解密（這是加密時的最後一步）
    base_seed = generate_seeds(key)
    total_size = size ** 3
    
    # 計算需要的替換表數量
    tables_needed = (len(ciphertext)) // block_size + 1
    tables = generate_multiple_sub_tables(key, tables_needed)
    
    # 多表解密
    recovered_text = []
    for i, c in enumerate(ciphertext):
        table_id = i // block_size
        if table_id < len(tables):
            _, dec_table = tables[table_id]
            recovered_text.append(dec_table.get(c, c))
        else:
            recovered_text.append(c)
    
    # 2. 3D矩陣換位復原
    # 先提取最後4位長度信息（加密時附加在展平矩陣後的末尾）
    length_str = ''.join(recovered_text[-4:])
    original_length = int(length_str)
    cipher_body = recovered_text[:-4]
    
    # 重新構建3D矩陣
    matrix = [[[None for _ in range(size)] for _ in range(size)] for _ in range(size)]
    coords = [(i, j, k) for i in range(size) for j in range(size) for k in range(size)]
    
    idx = 0
    dynamic_seed = base_seed
    while coords and idx < len(cipher_body):
        random.seed(dynamic_seed)
        pos = random.choice(coords)
        coords.remove(pos)
        i, j, k = pos
        matrix[i][j][k] = cipher_body[idx]
        char_val = ord(cipher_body[idx])
        dynamic_seed = (dynamic_seed * 131 + char_val + idx * 17) % (10**9 + 7)
        idx += 1
    
    # 展平3D矩陣
    flat_text = flatten_3d(matrix)
    
    # 3. 自定義Base32解碼（這是加密時的第一步）
    custom_alphabet = generate_playfair_key_string(key)
    base32_decoder = CustomBase32(custom_alphabet)
    try:
        decrypted = base32_decoder.decode(flat_text)
    except Exception as e:
        print(f"Base32解碼錯誤: {e}")
        return None
    
    # 返回原始長度的明文
    return decrypted[:original_length]


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
with open("key.txt", "r") as f:
    cipher_text_str = f.read()

encrypted_message = base64.b64decode(cipher_text_str)
# 解密
key = decipher.decrypt(encrypted_message).decode()
print("key：", key)

decrypted = decrypt(ciphertext, key)
print("解密：", decrypted)