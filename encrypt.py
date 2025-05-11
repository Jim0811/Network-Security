import random
from Crypto.PublicKey import RSA 
from Crypto.Cipher import PKCS1_OAEP 
import base64

# 原本的種子產生函數
def generate_seeds(key):
    base_seed = 0
    for c in key:
        base_seed = (base_seed * 131 + ord(c)) % (10**9 + 7)
    return base_seed

# 字元填充
def pad_text(text, size):
    charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
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

def generate_playfair_key_string(key: str) -> str:
    """Generate a 32-character custom alphabet from a key using Playfair rules."""
    DEFAULT_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    used_chars = set()
    processed_key = []
    
    # Process the key - remove duplicates but keep both I and J
    for c in key.upper():
        if c in DEFAULT_CHARS and c not in used_chars:
            processed_key.append(c)
            used_chars.add(c)
    
    # Add remaining characters from DEFAULT_CHARS
    for c in DEFAULT_CHARS:
        if c not in used_chars:
            processed_key.append(c)
    
    # Return exactly 32 characters for Base32
    return ''.join(processed_key[:32])
class CustomBase32:
    def __init__(self, alphabet: str):
        if len(alphabet) != 32:
            raise ValueError("Alphabet must be exactly 32 characters")
        self.alphabet = alphabet
        self.char_map = {c: i for i, c in enumerate(alphabet)}
    
    def encode(self, data: str) -> str:
        """Encode data using the custom Base32 alphabet."""
        if not data:
            return ""
        
        buffer = 0
        bits_left = 0
        output = []
        
        for byte in bytearray(data, 'utf-8'):
            buffer = (buffer << 8) | byte
            bits_left += 8
            
            while bits_left >= 5:
                bits_left -= 5
                index = (buffer >> bits_left) & 0x1F
                output.append(self.alphabet[index])
        
        # Handle remaining bits
        if bits_left > 0:
            index = (buffer << (5 - bits_left)) & 0x1F
            output.append(self.alphabet[index])
        
        return ''.join(output)


# 整合加密：換位 → 多表代換
def encrypt(plaintext, key, block_size=10):
    base_seed = generate_seeds(key)
    random.seed(base_seed)

    # --- Step 1: 自訂 Base32 encode ---
    custom_alphabet = generate_playfair_key_string(key)
    base32_encoder = CustomBase32(custom_alphabet)
    base32_plaintext = base32_encoder.encode(plaintext)

    # --- Step 2: 填充 + 轉 3D 矩陣 ---
    size = 9
    total_size = size ** 3
    padded = pad_text(base32_plaintext, total_size)
    matrix = to_3d_matrix(padded, size)

    # --- Step 3: 3D 矩陣換位 ---
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
    length_str = str(len(plaintext)).zfill(4)
    for c in length_str:
        flat_cipher.append(c)

    # --- Step 4: 多表代換 ---
    # 計算所需的表數量，確保足夠
    tables_needed = (total_size + len(length_str)) // block_size + 1
    tables = generate_multiple_sub_tables(key, tables_needed)
    
    final_cipher = []
    for i, c in enumerate(flat_cipher):
        table_id = i // block_size
        if table_id < len(tables):
            enc_table, _ = tables[table_id]
            final_cipher.append(enc_table.get(c, c))
        else:
            # 如果超出範圍，回傳原始字符（應該不會進入這部分，視情況處理）
            final_cipher.append(c)

    return ''.join(final_cipher), base_seed, size


plaintext = "se245d3c"
key = "34AZY"

# read public key
with open("de_public.pem", "rb") as f:
    de_public_key = RSA.import_key(f.read())

cipher = PKCS1_OAEP.new(de_public_key)
encrypted_message = cipher.encrypt(key.encode())
cipher_text_str = base64.b64encode(encrypted_message).decode()
with open("key.txt", "w") as f:
    f.write(cipher_text_str)

ciphertext, seed, size = encrypt(plaintext, key)
print("明文：", plaintext)
print("密文：", ciphertext)