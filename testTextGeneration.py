# 生成测试数据

import json
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

SECRET_KEY = b'YourSecretKey123'
IV = b'InitializationVe'

test_data = {
    "grade": 1,
    "students": [
        {
            "name": "张三",
            "password_hash": hashlib.sha256("123456".encode()).hexdigest(), #密码
            "scores": {"语文", "数学", "英语","生物","地理","历史","道德与法治"}, #科目
            "rank": 5 #年级排名
        },
        {
            "name": "李四",
            "password_hash": hashlib.sha256("abcdef".encode()).hexdigest(),
            "scores": {"语文": 88, "数学": 92, "英语": 89, "化学": 95},
            "rank": 3
        }
    ]
}

test_data = {
    "grade": 2,
    "students": [
        {
            "name": "王五",
            "password_hash": hashlib.sha256("111111".encode()).hexdigest(), #密码
            "scores": {"语文", "数学", "英语", "物理","生物","地理","历史","道德与法治"}, #科目
            "rank": 11 #年级排名
        },
        {
            "name": "赵六",
            "password_hash": hashlib.sha256("000000".encode()).hexdigest(),
            "scores": {"语文", "数学", "英语", "物理","生物","地理","历史","道德与法治"},
            "rank": 3
        }
    ]
}

cipher = AES.new(SECRET_KEY, AES.MODE_CBC, IV)
encrypted_data = cipher.encrypt(pad(json.dumps(test_data).encode(), AES.block_size))
with open('grade_1.enc', 'wb') as f:
    f.write(encrypted_data)