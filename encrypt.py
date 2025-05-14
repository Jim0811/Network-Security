import random
from Crypto.PublicKey import RSA 
from Crypto.Cipher import PKCS1_OAEP 
import base64
import numpy as np
from scipy.integrate import solve_ivp
import string

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

# 原本的種子產生函數
def generate_seeds(key):
    base_seed = 0
    for c in key:
        base_seed = (base_seed * 131 + ord(c)) % (10**9 + 7)
    return base_seed

# 字元填充
def pad_text(text, size):
    charset = 'abcdefghijklmnopqrstuvwxyz0123456789'
    random.seed(key)
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
    charset = list('abcdefghijklmnopqrstuvwxyz0123456789')
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
    DEFAULT_CHARS = "abcdefghijklmnopqrstuvwxyz0123456789"
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

# 定義明文和密文的字符集
charset = string.digits + string.ascii_lowercase  # '0123456789abcdefghijklmnopqrstuvwxyz'
charset_size = len(charset)

# 字符到索引和索引到字符的映射
char_to_idx = {c: i for i, c in enumerate(charset)}
idx_to_char = {i: c for i, c in enumerate(charset)}

# 微分方程參數和求解器
# 使用一個簡單的二階ODE: y'' + k1(x)*y' + k0(x)*y = 0
# 簡化起見，k0和k1將是由金鑰K定義的多項式

# 將金鑰字符串K轉換為k0和k1的多項式係數
# 為演示，將K分成兩半，分別作為k0和k1的係數
# 如果K長度為奇數，則用零填充

def key_to_coeffs(K):
    n = len(K)
    half = (n + 1) // 2
    k0_coeffs = [ord(c) % 10 for c in K[:half]]
    k1_coeffs = [ord(c) % 10 for c in K[half:]]
    # 填充到相同長度
    max_len = max(len(k0_coeffs), len(k1_coeffs))
    k0_coeffs += [0] * (max_len - len(k0_coeffs))
    k1_coeffs += [0] * (max_len - len(k1_coeffs))
    return k0_coeffs, k1_coeffs

# 多項式求值
def poly_eval(coeffs, x):
    return sum(c * x**i for i, c in enumerate(coeffs))

# 定義solve_ivp的ODE系統
def ode_system(x, y, k0_coeffs, k1_coeffs):
    y1, y2 = y
    k0 = poly_eval(k0_coeffs, x)
    k1 = poly_eval(k1_coeffs, x)
    dy1dx = y2
    dy2dx = -k1 * y2 - k0 * y1
    return [dy1dx, dy2dx]

# 從ODE解生成排列sigma
def generate_permutation(K, N, X=5, a=2, b=1):
    k0_coeffs, k1_coeffs = key_to_coeffs(K)
    x_span = (0, X)
    x_eval = np.linspace(0, X, N+1)
    sol = solve_ivp(ode_system, x_span, [a, b], t_eval=x_eval, args=(k0_coeffs, k1_coeffs), method='RK45')
    y_vals = sol.y[0, 1:]  # 排除初始點 y(0)

    # 歸一化並生成索引
    max_abs = np.max(np.abs(y_vals))
    s = np.floor((np.abs(y_vals) / max_abs) * (N - 1)).astype(int)  # changed N to N-1 to avoid out of bounds

    # 修正重複和缺失的索引以形成有效的排列
    used = set()
    permutation = []
    missing = [i for i in range(N) if i not in s]
    miss_idx = 0
    for val in s:
        if val not in used:
            permutation.append(val)
            used.add(val)
        else:
            permutation.append(missing[miss_idx])
            miss_idx += 1
    
    return permutation


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
    seed_point = (base_seed % p, (base_seed * 32452843) % p)
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
    length_str = str(len(base32_plaintext)).zfill(4)
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
 
    #ho's encrypt
    #轉成any
    third_cipher = ''.join(final_cipher)
    # 將明文轉換為索引
    indices = [char_to_idx[c] for c in third_cipher]
    N = 10  # 矩陣的列數（可以參數化）
    # 將明文填充到N的倍數
    L = ((len(indices) + N - 1) // N) * N
    pad_len = L - len(indices)
    # 填充字符由金鑰生成 (簡單地重複第一個字符索引)
    pad_char_idx = char_to_idx[key[0]] if key else 0 # 使用金鑰的第一個字元
    indices += [pad_char_idx] * pad_len
    # 創建矩陣
    rows = L // N
    matrix = np.array(indices).reshape(rows, N)
    # 生成排列
    sigma = generate_permutation(key, N)
    # 將排列應用於列
    permuted_matrix = matrix[:, sigma]
    # 逐行讀取密文
    ciphertext_indices = permuted_matrix.flatten()
    last_cipher = ''.join(idx_to_char[i] for i in ciphertext_indices)

    return ''.join(last_cipher), base_seed, size


plaintext = "ksdif"
key = "011"

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