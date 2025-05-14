import random
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64
import numpy as np
from scipy.integrate import solve_ivp
import string

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

def generate_playfair_key_string(key: str) -> str:
    DEFAULT_CHARS = "abcdefghijklmnopqrstuvwxyz0123456789"
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

def decrypt(ciphertext, key, size=9, block_size=10):
    #ho's decrypt
    # 將密文轉換為索引
    indices = [char_to_idx[c] for c in ciphertext]
    N = 10  # 矩陣的列數 (必須與加密時相同)
    L = len(indices)
    rows = L // N
    matrix = np.array(indices).reshape(rows, N)
    # 生成排列
    sigma = generate_permutation(key, N)
    # 計算逆排列
    inv_sigma = np.argsort(sigma)
    # 應用逆排列
    original_matrix = matrix[:, inv_sigma]
    # 扁平化並移除填充
    plaintext_indices = original_matrix.flatten()
    # 通過修剪尾部的pad_char_idx來移除填充
    pad_char_idx = char_to_idx[key[0]] if key else 0 # 使用金鑰的第一個字元
    while len(plaintext_indices) > 0 and plaintext_indices[-1] == pad_char_idx:
        plaintext_indices = plaintext_indices[:-1]
    first_plaintext = ''.join(idx_to_char[i] for i in plaintext_indices)

    # 1. 首先進行多表代換解密（這是加密時的最後一步）
    base_seed = generate_seeds(key)
    total_size = size ** 3
    
    # 計算需要的替換表數量
    tables_needed = (len(first_plaintext)) // block_size + 1
    tables = generate_multiple_sub_tables(key, tables_needed)
    
    # 多表解密
    recovered_text = []
    for i, c in enumerate(first_plaintext):
        table_id = i // block_size
        if table_id < len(tables):
            _, dec_table = tables[table_id]
            recovered_text.append(dec_table.get(c, c))
        else:
            recovered_text.append(c)
    
    aplain = ''.join(recovered_text)
    # 2. 3D矩陣換位復原
    # 先提取最後4位長度信息（加密時附加在展平矩陣後的末尾）
    length_str = ''.join(recovered_text[-4:])
    original_length = int(length_str)
    cipher_body = recovered_text[:-4]
    
    # 重新構建3D矩陣
    matrix = [[[None for _ in range(size)] for _ in range(size)] for _ in range(size)]
    coords = [(i, j, k) for i in range(size) for j in range(size) for k in range(size)]
    
    idx = 0
    seed_point = (base_seed % p, (base_seed * 32452843) % p)
    while coords and idx < len(cipher_body):
        pos_idx = seed_point[0] % len(coords)
        pos = coords.pop(pos_idx)

        i, j, k = pos
        matrix[i][j][k] = cipher_body[idx]

        seed_point = point_add(seed_point, G)

        idx += 1
    
    # 展平3D矩陣
    flat_text = flatten_3d(matrix)
    flat_text = flat_text[:original_length]
    
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