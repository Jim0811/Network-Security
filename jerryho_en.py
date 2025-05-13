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


# 加密函數
def encrypt(plaintext, K):
    # 將明文轉換為索引
    indices = [char_to_idx[c] for c in plaintext]
    N = 10  # 矩陣的列數（可以參數化）
    # 將明文填充到N的倍數
    L = ((len(indices) + N - 1) // N) * N
    pad_len = L - len(indices)
    # 填充字符由金鑰生成 (簡單地重複第一個字符索引)
    pad_char_idx = char_to_idx[K[0]] if K else 0 # 使用金鑰的第一個字元
    indices += [pad_char_idx] * pad_len
    # 創建矩陣
    rows = L // N
    matrix = np.array(indices).reshape(rows, N)
    # 生成排列
    sigma = generate_permutation(K, N)
    # 將排列應用於列
    permuted_matrix = matrix[:, sigma]
    # 逐行讀取密文
    ciphertext_indices = permuted_matrix.flatten()
    ciphertext = ''.join(idx_to_char[i] for i in ciphertext_indices)
    return ciphertext





