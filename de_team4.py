import math
import strokes

def morse_encode(char):
    morse_dict = {
        'a': '.-', 'b': '-...', 'c': '-.-.', 'd': '-..', 'e': '.', 'f': '..-.', 
        'g': '--.', 'h': '....', 'i': '..', 'j': '.---', 'k': '-.-', 'l': '.-..', 
        'm': '--', 'n': '-.', 'o': '---', 'p': '.--.', 'q': '--.-', 'r': '.-.', 
        's': '...', 't': '-', 'u': '..-', 'v': '...-', 'w': '.--', 'x': '-..-', 
        'y': '-.--', 'z': '--..','0' :'-----','2' :'..---','3' :'...--','4' :'....-',
        '5' :'.....','6' :'-....','7' :'--...','8' :'---..','9' :'----.'
    }
    return morse_dict.get(char.lower(), '')

def is_prime(n):
    """判斷一個數是否為質數"""
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0 or n % 3 == 0:
        return False
    i = 5
    while i * i <= n:
        if n % i == 0 or n % (i + 2) == 0:
            return False
        i += 6
    return True

def process_key(key):
    """處理key: 轉為mod36的數字，拆分十位數，去除重複"""
    key_nums = []
    for char in key:
        if '0' <= char <= '9':
            key_nums.append(int(char))
        elif 'a' <= char <= 'z':
            key_nums.append(ord(char) - ord('a') + 10)
        else:
            key_nums.append(ord(char) % 36)
    #print("key_num :",key_nums)

    # 拆分個位數
    expanded_nums = []
    for num in key_nums:
        if num >= 10:
            expanded_nums.append(num // 10)
            expanded_nums.append(num % 10)
        else:
            expanded_nums.append(num)
    #print("expanded_nums :",expanded_nums)

    # 去除重複，保留首次出現的順序
    unique_nums = []
    for num in expanded_nums:
        if num not in unique_nums:
            unique_nums.append(num)
    #print("unique :",unique_nums)

    return unique_nums
def get_l_sequence(lyrics):
    l_values = []
    for i, ch in enumerate(lyrics, start=1):
        try:
            count = strokes.strokes(ch)
            l_values.append(count % 36)
        except Exception as e:
            l_values.append(0)
    return l_values

P = [30, 17, 28, 34, 16, 23, 23, 22, 16, 17, 29, 29, 22, 21, 20, 22, 22, 24, 22, 16, 22, 18, 29, 30, 20, 30, 23, 23, 21, 21, 30, 26, 30, 28, 22, 17, 30, 17, 28, 34, 16, 23, 23]
lyrics = "說過多少遍要聽話一點不要再狡辯拒絕是欺騙看著我的眼說再來一遍讓妳感到性福滿點求我再一遍"  # 43字
alphabet = '0123456789abcdefghijklmnopqrstuvwxyz'
char_to_num = {ch: i for i, ch in enumerate(alphabet)}
num_to_char = {i: ch for i, ch in enumerate(alphabet)}

L = get_l_sequence(lyrics)

def shift_left(arr, n):
    n = n % len(arr)
    return arr[n:] + arr[:n]

def decrypt(ciphertext, key, P, L):
     # 如果密文長度不是偶數，則在最後補一個'x'
    if len(ciphertext) % 2 != 0:
        # 計算'x'對應的密文字符
        # 根據加密過程，我們知道'x'被放在L1的第一個位置
        # 因此需要在密文的開頭添加對應的字符
        x_code = 33  # 'x'的ASCII代碼為33
        ciphertext = chr(x_code) + ciphertext
    
    # 將密文轉為數字
    ciphertext_nums = []
    for char in ciphertext:
        if '0' <= char <= '9':
            ciphertext_nums.append(int(char))
        elif 'a' <= char <= 'z':
            ciphertext_nums.append(ord(char) - ord('a') + 10)
        else:
            ciphertext_nums.append(ord(char) % 36)


    # 分為前半段和後半段
    mid = len(ciphertext_nums) // 2
    L1 = ciphertext_nums[:mid]
    R1 = ciphertext_nums[mid:]
    #print(L1,R1)
    # 計算seed, a, b, perm_seed
    seed = sum(ord(char) for char in key)
    
    # 計算a
    a = seed % 36
    while math.gcd(a, 36) != 1:
        a += 1
        if a >= 36:
            a = 1
    
    # 計算b
    b = (seed + ord(key[-1])) % 36
    
    # 計算perm_seed
    perm_seed = ord(key[0]) % 100
    
    # 計算rank_L1
    rank_L1 = []
    perm_values = [(perm_seed * 37 * j) % 100 for j in range(1, len(L1) + 1)]
    
    # 創建一個包含值和原始索引的列表
    val_idx = [(val, i) for i, val in enumerate(perm_values)]
    
    # 按值降序排序
    val_idx_sorted = sorted(val_idx, key=lambda x: x[0], reverse=True)
    
    # 創建一個與原始列表等長的排名列表
    rank_L1 = [0] * len(perm_values)
    
    # 為每個原始索引位置分配排名（最大值獲得最大排名）
    max_rank = len(perm_values) - 1
    for i, (_, original_idx) in enumerate(val_idx_sorted):
        rank_L1[original_idx] = max_rank - i
    
    # 還原R0
    R0 = [0] * len(L1)
    for i, pos in enumerate(rank_L1):
        R0[i] = L1[pos]
    #print("R0 = ",R0)

    # 計算F
    F = [(a * R0[i] + b) % 36 for i in range(len(R0))]
    
    # 根據F的大小排序得到rank_R1（修改後的方式）
    val_idx = [(val, i) for i, val in enumerate(F)]
    val_idx_sorted = sorted(val_idx, key=lambda x: x[0], reverse=True)

    # 創建一個與原始列表等長的排名列表
    rank_R1 = [0] * len(F)

    # 為每個原始索引位置分配排名（最大值獲得最大排名）
    max_rank = len(F) - 1
    for i, (_, original_idx) in enumerate(val_idx_sorted):
        rank_R1[original_idx] = max_rank - i
    #print("rank_R1 = ",rank_R1)

    # 還原R1的原始順序
    R1_original = [0] * len(R1)
    for i, pos in enumerate(rank_R1):
        R1_original[i] = R1[pos]
    
    # 計算L0
    L0 = [(R1_original[i] - F[i]) % 36 for i in range(len(R1_original))]
    
    # 合併L0和R0
    plaintext_nums = L0 + R0
    #print(plaintext_nums)

    # 將數字轉回字符
    plaintext6 = ''
    for num in plaintext_nums:
        if 0 <= num <= 9:
            plaintext6 += str(num)
        else:
            plaintext6 += chr(num - 10 + ord('a'))
    
    # 如果最後有補'x'則刪除
    if plaintext6[-1] == 'x':
        plaintext6 = plaintext6[:-1]
    print(plaintext6)
###################################################
    # 處理key
    processed_key = process_key(key)
    cols = len(processed_key)
    
    # 獲取填充計數
    padding_count = int(char_to_num[plaintext6[0]])
    plaintext6 = plaintext6[1:]
    
    # 計算行數
    rows = len(plaintext6) // cols
    
    # 獲取列的順序
    col_order = [(num, i) for i, num in enumerate(processed_key)]
    col_order.sort()
    
    # 創建空矩陣
    matrix = [[''] * cols for _ in range(rows)]
    
    # 填充矩陣
    idx = 0
    for _, col_idx in col_order:
        for row in range(rows):
            matrix[row][col_idx] = plaintext6[idx]
            idx += 1
    
    # 讀取矩陣
    plaintext5 = ''
    for row in matrix:
        plaintext5 += ''.join(row)
    print(plaintext5)
    # 移除填充
    # plaintext5 = plaintext5[:-padding_count] if padding_count > 0 else plaintext5
#####################################################################
    plaintext4 = ''
    key_num = 0
    # Key 字串轉數字 list
    key_num = [char_to_num[ch] for ch in key]
    
    for i in range(len(plaintext5)):
        c_val = char_to_num[plaintext5[i]]
        p_val = P[i]
        l_val = L[i]
        k_val = char_to_num[key[0]]
    
        plain_val = (c_val - k_val - l_val - p_val) % 36
        plaintext4 += num_to_char[plain_val]
    
        shift_amount = p_val ^ l_val
        key = shift_left(key, shift_amount)
    print(plaintext4)
#####################################################################
    # 轉換key為數字
    key_num=0
    for char in key:
        if '0' <= char <= '9':
            key_num = (key_num * 10 + int(char)) % 6
        elif 'a' <= char <= 'z':
            key_num = (key_num * 10 + (ord(char) - ord('a') + 10)) % 6
    
    
    # 獲取填充計數
    padding_count = int(char_to_num[plaintext4[0]])
    plaintext4 = plaintext4[1:]
    
    # 計算矩陣大小
    matrix_size = math.ceil(math.sqrt(len(plaintext4) - padding_count + padding_count))
    
    # 創建空矩陣
    matrix = [[''] * matrix_size for _ in range(matrix_size)]
    
    # 收集座標總和相同的位置
    sum_to_coords = {}
    for i in range(matrix_size):
        for j in range(matrix_size):
            sum_val = i + j
            if sum_val not in sum_to_coords:
                sum_to_coords[sum_val] = []
            sum_to_coords[sum_val].append((i, j))
    
    # 對於每個總和，按照從右上到左下的順序排序
    for sum_val in sum_to_coords:
        sum_to_coords[sum_val].sort(key=lambda coord: (coord[0], -coord[1]))
    
    # 計算每類字符的數量
    prime_count = 0
    even_count = 0
    odd_count = 0
    
    for sum_val in sorted(sum_to_coords.keys()):
        for i, j in sum_to_coords[sum_val]:
            coord_sum = i + j
            if is_prime(coord_sum):
                prime_count += 1
            elif coord_sum % 2 == 0:
                even_count += 1
            else:
                odd_count += 1
    
    # 6種可能的讀取順序
    orders = [
        ["P", "E", "O"],    # P→E→O
        ["P", "O", "E"],    # P→O→E
        ["O", "P", "E"],    # O→P→E
        ["E", "P", "O"],    # E→P→O
        ["E", "O", "P"],    # E→O→P
        ["O", "E", "P"]     # O→E→P
    ]
    
    # 選擇讀取順序
    order = orders[key_num]
    
    # 根據順序分割密文
    segments = []
    idx = 0
    for segment_type in order:
        if segment_type == "P":
            segments.append(plaintext4[idx:idx+prime_count])
            idx += prime_count
        elif segment_type == "E":
            segments.append(plaintext4[idx:idx+even_count])
            idx += even_count
        else:  # segment_type == "O"
            segments.append(plaintext4[idx:idx+odd_count])
            idx += odd_count
    
    # 將字符放回矩陣
    prime_idx = 0
    even_idx = 0
    odd_idx = 0
    
    for sum_val in sorted(sum_to_coords.keys()):
        for i, j in sum_to_coords[sum_val]:
            coord_sum = i + j
            if is_prime(coord_sum):
                segment_idx = order.index("P")
                matrix[i][j] = segments[segment_idx][prime_idx]
                prime_idx += 1
            elif coord_sum % 2 == 0:
                segment_idx = order.index("E")
                matrix[i][j] = segments[segment_idx][even_idx]
                even_idx += 1
            else:
                segment_idx = order.index("O")
                matrix[i][j] = segments[segment_idx][odd_idx]
                odd_idx += 1
    
    # 讀取矩陣
    plaintext3 = ''
    for i in range(matrix_size):
        for j in range(matrix_size):
            plaintext3 += matrix[i][j]
    
    # 移除填充
    plaintext3 = plaintext3[:-padding_count] if padding_count > 0 else plaintext3
##################################################################################
    # 創建6x6表格
    table = [['' for _ in range(6)] for _ in range(6)]
    
    # 處理key，去除重複字符
    processed_key = []
    for char in key:
        if char not in processed_key:
            processed_key.append(char)
    
    # 所有可能的字符（數字和小寫字母）
    all_chars = '0123456789abcdefghijklmnopqrstuvwxyz'
    
    # 填充表格
    index = 0
    # 先填入key
    for char in processed_key:
        row = index // 6
        col = index % 6
        table[row][col] = char
        index += 1
    
    # 填入剩餘字符
    for char in all_chars:
        if char not in processed_key:
            row = index // 6
            col = index % 6
            table[row][col] = char
            index += 1
    
    # 獲取π的小數部分
    pi_digits = str(math.pi)[2:]
    
    # 解密
    plaintext2 = ''
    for i, char in enumerate(plaintext3):
        # 找到字符在表格中的位置
        found = False
        for r in range(6):
            for c in range(6):
                if table[r][c] == char:
                    row, col = r, c
                    found = True
                    break
            if found:
                break
        
        # 根據π的數字決定移動方向和步數
        pi_digit = int(pi_digits[i % len(pi_digits)])
        direction = pi_digit % 8  # 8個方向
        steps = pi_digit % 6      # 最多移動5步
        
        # 移動方向對應的行列變化（與加密相反）
        directions = [
            (1, 0),    # 下
            (1, -1),    # 左下
            (0, -1),   # 左
            (-1, -1),  # 左上
            (-1, 0),   # 上
            (-1, 1),   # 右上
            (0, 1),    # 右
            (1, 1)    # 右下
        ]
        
        # 移動
        for _ in range(steps):
            dr, dc = directions[direction]
            row = (row + dr) % 6  # 環形連接
            col = (col + dc) % 6  # 環形連接
        
        # 加入明文
        plaintext2 += table[row][col]

################################################

    # 限制密文長度為5
    if len(plaintext2) != 5:
        raise ValueError("密文長度必須為5")
    
    # Step 1: 將key轉換為摩斯電碼
    subkey = ''.join(morse_encode(c) for c in key)
    
    # Step 2: 將subkey分為兩個兩個一組
    subkey_pairs = [subkey[i:i+2] for i in range(0, len(subkey), 2)]
    
    # 計算subkey中.-、..、--、-.分別出現的次數
    count_a = subkey_pairs.count('.-')  # a
    count_i = subkey_pairs.count('..')  # i
    count_m = subkey_pairs.count('--')  # m
    count_n = subkey_pairs.count('-.')  # n
    
    # 創建映射表，指定優先順序
    priority_map = {'i': 0, 'a': 1, 'n': 2, 'm': 3}
    
    # 根據出現次數排序，如果相同則按照i,a,n,m的順序
    counts = [(count_i, 'i'), (count_a, 'a'), (count_n, 'n'), (count_m, 'm')]
    counts.sort(key=lambda x: (x[0], priority_map[x[1]]))  # 按照計數和優先順序排序
    
    # 獲取排序後的索引
    order = [c[1] for c in counts]
    
    # 創建映射表
    mapping = {'i': 1, 'm': 2, 'a': 0, 'n': 3}
    
    # Step 2: 如果subkey長度為奇數，則將第一位移到最後一個
    result = list(plaintext2)
    if len(subkey) % 2 == 1:
        result = result[1:] + [result[0]]
    
    # Step 3: 還原明文
    plaintext = [''] * 5
    for i, char_type in enumerate(order):
        plaintext[mapping[char_type]] = result[i]
    
    # 最後一個字符保持不變
    plaintext[4] = result[4]
    
    return ''.join(plaintext)

# 測試
if __name__ == "__main__":
    encrypted = "9vxq2cz91n2av"
    key = "annji"

    decrypted = decrypt(encrypted, key, P, L)
    print(f"解密後: {decrypted}")

