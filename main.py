import random
import string

def generate_key(length):
    # 定義字元範圍 0-9 + a-z
    characters = string.digits + string.ascii_lowercase
    # 隨機抽取 length 個字元組成金匙
    key = ''.join(random.choice(characters) for _ in range(length))
    return key

# 範例：產生長度 10 的金匙
key = generate_key(5)
print("隨機金匙：", key)