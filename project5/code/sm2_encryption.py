import os
import hashlib
import random  # 添加random导入
from sm2_params import n
from sm2_ec import G, Point, point_multiply, is_on_curve

def kdf(Z, klen):
    """
    密钥派生函数
    Z: 输入的字节串
    klen: 需要的密钥长度(比特)
    """
    ct = 1
    K = b''
    v = 32  # SM3摘要长度为32字节(256比特)
    
    for i in range((klen + 255) // 256):  # 向上取整
        K += hashlib.sha256(Z + ct.to_bytes(4, byteorder='big')).digest()
        ct += 1
    
    return K[:((klen + 7) // 8)]  # 转换为字节长度并截取所需长度


def encrypt(message, public_key):
    """
    SM2加密算法
    message: 待加密消息（字节串）
    public_key: 接收方公钥点P
    """
    message_len = len(message)
    
    while True:
        # 1. 生成随机数k∈[1,n-1]
        k = random.randint(1, n-1)
        
        # 2. 计算 C1 = k*G
        C1 = point_multiply(k, G)
        
        # 将C1编码为字节串
        C1_encoded = b'\x04' + C1.x.to_bytes(32, byteorder='big') + C1.y.to_bytes(32, byteorder='big')
        
        # 3. 计算 kP = k*PB = (x2, y2)
        kP = point_multiply(k, public_key)
        
        if kP.infinity:
            continue
        
        # 4. 计算 t = KDF(x2||y2, klen)
        x2_bytes = kP.x.to_bytes(32, byteorder='big')
        y2_bytes = kP.y.to_bytes(32, byteorder='big')
        Z = x2_bytes + y2_bytes
        t = kdf(Z, message_len * 8)
        
        # 检查t是否全为0
        if all(b == 0 for b in t):
            continue
        
        # 5. 计算 C2 = M ⊕ t
        C2 = bytes(m ^ t[i] for i, m in enumerate(message))
        
        # 6. 计算 C3 = Hash(x2 || M || y2)
        h = hashlib.sha256()
        h.update(x2_bytes + message + y2_bytes)
        C3 = h.digest()
        
        # 7. 输出密文 C = C1 || C3 || C2
        return C1_encoded + C3 + C2

def decrypt(ciphertext, private_key):
    """
    SM2解密算法
    ciphertext: 密文C=C1||C3||C2
    private_key: 接收方私钥d
    """
    # 1. 从C中分离出C1、C3和C2
    if ciphertext[0] != 0x04:
        raise ValueError("不支持的C1编码格式")
    
    # C1为65字节: 标识符(1字节) + x坐标(32字节) + y坐标(32字节)
    C1_x = int.from_bytes(ciphertext[1:33], byteorder='big')
    C1_y = int.from_bytes(ciphertext[33:65], byteorder='big')
    C1 = Point(C1_x, C1_y)
    
    # 验证C1是否在曲线上
    if not is_on_curve(C1):
        raise ValueError("C1不在椭圆曲线上")
    
    # C3为哈希值，长度32字节
    C3 = ciphertext[65:97]
    
    # C2为剩余部分
    C2 = ciphertext[97:]
    
    # 2. 计算 d*C1 = (x2, y2)
    dC1 = point_multiply(private_key, C1)
    
    if dC1.infinity:
        raise ValueError("无效的点乘结果")
    
    # 3. 计算 t = KDF(x2||y2, klen)，klen为C2的比特长度
    x2_bytes = dC1.x.to_bytes(32, byteorder='big')
    y2_bytes = dC1.y.to_bytes(32, byteorder='big')
    Z = x2_bytes + y2_bytes
    t = kdf(Z, len(C2) * 8)
    
    # 4. 计算 M' = C2 ⊕ t
    message = bytes(c ^ t[i] for i, c in enumerate(C2))
    
    # 5. 计算 u = Hash(x2 || M' || y2)
    h = hashlib.sha256()
    h.update(x2_bytes + message + y2_bytes)
    u = h.digest()
    
    # 6. 验证 u == C3
    if u != C3:
        raise ValueError("解密验证失败")
    
    # 7. 输出明文M'
    return message
