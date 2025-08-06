import random
from sm2_params import n, p, a, b
from sm2_ec import G, point_multiply, Point

def generate_key_pair():
    """生成SM2密钥对"""
    # 随机生成私钥 d∈[1,n-2]
    d = random.randint(1, n-2)
    
    # 计算公钥 P = d * G
    P = point_multiply(d, G)
    
    return d, P

def compress_public_key(P):
    """公钥压缩"""
    if P.infinity:
        return bytes([0])
    
    # 判断y坐标的奇偶性
    prefix = 3 if P.y & 1 else 2
    # 返回压缩公钥
    return bytes([prefix]) + P.x.to_bytes(32, byteorder='big')

def decompress_public_key(compressed_key):
    """解压缩公钥"""
    if compressed_key[0] == 0:
        return Point.infinity_point()
    
    x = int.from_bytes(compressed_key[1:], byteorder='big')
    prefix = compressed_key[0]
    
    # 计算 y²
    alpha = (pow(x, 3, p) + a * x + b) % p
    
    # SM2曲线满足p ≡ 3 (mod 4)，因此可以直接使用以下公式计算平方根
    y = pow(alpha, (p + 1) // 4, p)
    
    # 根据前缀调整y的奇偶性
    if (prefix == 2 and y & 1 == 1) or (prefix == 3 and y & 1 == 0):
        y = p - y
    
    # 验证点是否在曲线上
    from sm2_ec import is_on_curve
    point = Point(x, y)
    if not is_on_curve(point):
        raise ValueError("解压缩得到的点不在曲线上")
    
    return point
