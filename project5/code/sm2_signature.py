import hashlib
import random
from sm2_params import n
from sm2_ec import G, point_multiply, point_add, mod_inverse

def sm3_hash(data):
    """使用SM3哈希算法 (此处用SHA-256代替，实际应使用SM3)"""
    return int(hashlib.sha256(data).hexdigest(), 16)


def sign(message, private_key, Z=None):
    """
    SM2签名算法
    message: 待签名消息（字节串）
    private_key: 私钥d
    Z: 用户身份标识符（可选），如果未提供则使用默认值
    """
    if Z is None:
        # 默认用户标识符
        Z = b'1234567812345678'
    
    # 1. 计算消息摘要
    M = Z + message
    e = sm3_hash(M)
    
    while True:
        # 2. 生成随机数 k∈[1,n-1]
        k = random.randint(1, n-1)
        
        # 3. 计算 (x1,y1) = k*G
        point = point_multiply(k, G)
        x1 = point.x
        
        # 4. 计算 r = (e + x1) mod n
        r = (e + x1) % n
        if r == 0 or r + k == n:
            continue  # 如果r=0或r+k=n，则返回步骤2重新生成随机数k
        
        # 5. 计算 s = ((1 + d)^-1 * (k - r*d)) mod n
        s = (mod_inverse(1 + private_key, n) * (k - r * private_key % n) % n) % n
        if s == 0:
            continue  # 如果s=0，则返回步骤2重新生成随机数k
        
        return (r, s)

def verify(message, signature, public_key, Z=None):
    """
    SM2验签算法
    message: 待验证消息（字节串）
    signature: 签名值 (r,s)
    public_key: 公钥点P
    Z: 用户身份标识符（可选），如果未提供则使用默认值
    """
    r, s = signature
    
    # 检查签名格式
    if r < 1 or r > n-1 or s < 1 or s > n-1:
        return False
    
    if Z is None:
        # 默认用户标识符
        Z = b'1234567812345678'
    
    # 1. 计算消息摘要
    M = Z + message
    e = sm3_hash(M)
    
    # 2. 计算 t = (r + s) mod n
    t = (r + s) % n
    if t == 0:
        return False
    
    # 3. 计算 (x1',y1') = s*G + t*P
    P1 = point_multiply(s, G)
    P2 = point_multiply(t, public_key)
    point = point_add(P1, P2)
    x1 = point.x
    
    # 4. 计算 R = (e + x1') mod n
    R = (e + x1) % n
    
    # 5. 验证 R == r
    return R == r
