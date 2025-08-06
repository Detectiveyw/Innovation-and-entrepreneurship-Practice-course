import random
from sm2_params import p, a, b, n, Gx, Gy

class Point:
    """椭圆曲线上的点"""
    def __init__(self, x, y):
        self.x = x
        self.y = y
        self.infinity = False
    
    @classmethod
    def infinity_point(cls):
        """返回无穷远点"""
        point = cls(0, 0)
        point.infinity = True
        return point
    
    def __eq__(self, other):
        if self.infinity and other.infinity:
            return True
        if self.infinity or other.infinity:
            return False
        return (self.x == other.x) and (self.y == other.y)
    
    def __str__(self):
        if self.infinity:
            return "Point(∞)"
        return f"Point({hex(self.x)}, {hex(self.y)})"

def extended_gcd(a, b):
    """扩展欧几里得算法，计算模逆元素"""
    if a == 0:
        return b, 0, 1
    else:
        gcd, x, y = extended_gcd(b % a, a)
        return gcd, y - (b // a) * x, x

def mod_inverse(k, p):
    """计算 k 模 p 的乘法逆元"""
    if k == 0:
        raise ZeroDivisionError("除数不能为 0")
    
    # 处理负数
    k = k % p
    
    gcd, x, y = extended_gcd(k, p)
    if gcd != 1:
        raise ValueError(f"模 {p} 下不存在逆元")
    else:
        return (x % p + p) % p

def point_add(P, Q):
    """椭圆曲线上的点加法运算"""
    if P.infinity:
        return Q
    if Q.infinity:
        return P
    
    if P.x == Q.x:
        if (P.y + Q.y) % p == 0:
            return Point.infinity_point()
        else:
            return point_double(P)
    
    # 计算斜率
    slope = ((Q.y - P.y) * mod_inverse(Q.x - P.x, p)) % p
    
    # 计算 x3, y3
    x3 = (slope ** 2 - P.x - Q.x) % p
    y3 = (slope * (P.x - x3) - P.y) % p
    
    return Point(x3, y3)

def point_double(P):
    """椭圆曲线上的点倍加运算"""
    if P.infinity:
        return P
    
    if P.y == 0:
        return Point.infinity_point()
    
    # 计算斜率
    slope = ((3 * P.x ** 2 + a) * mod_inverse(2 * P.y, p)) % p
    
    # 计算 x3, y3
    x3 = (slope ** 2 - 2 * P.x) % p
    y3 = (slope * (P.x - x3) - P.y) % p
    
    return Point(x3, y3)

def point_multiply(k, P):
    """标量乘法，k*P"""
    if k == 0 or P.infinity:
        return Point.infinity_point()
    
    if k < 0:
        return point_multiply(-k, Point(P.x, (-P.y) % p))
    
    result = Point.infinity_point()
    addend = P
    
    while k:
        if k & 1:  # k 的二进制最低位为 1
            result = point_add(result, addend)
        addend = point_double(addend)
        k >>= 1  # k 右移一位
    
    return result

# 基点 G
G = Point(Gx, Gy)

def is_on_curve(P):
    """检查点 P 是否在椭圆曲线上"""
    if P.infinity:
        return True
    
    left = (P.y ** 2) % p
    right = (P.x ** 3 + a * P.x + b) % p
    return left == right
