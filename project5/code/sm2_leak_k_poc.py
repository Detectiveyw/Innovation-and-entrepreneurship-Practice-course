import random  # 添加random导入
from sm2_params import n
from sm2_ec import G, point_multiply, mod_inverse
from sm2_keygen import generate_key_pair  # 添加需要的函数
from sm2_signature import sm3_hash  # 添加sm3_hash导入

def recover_private_key_from_leaked_k(message, signature, k, Z=None):
    """
    通过泄露的随机数k恢复私钥
    message: 签名的消息
    signature: (r,s)签名值
    k: 泄露的随机数
    Z: 用户标识符
    
    返回: 恢复的私钥d
    """
    if Z is None:
        Z = b'1234567812345678'
    
    r, s = signature
    
    # 计算消息摘要 e
    M = Z + message
    e = sm3_hash(M)
    
    # 根据SM2签名方程: s = ((1 + d)^-1 * (k - r*d)) mod n
    # 我们可以推导出: (1 + d)*s ≡ k - r*d (mod n)
    # 即: s + d*s ≡ k - r*d (mod n)
    # 整理得: d*(s + r) ≡ k - s (mod n)
    # 因此: d ≡ (k - s) * (s + r)^-1 (mod n)
    
    # 计算 (s + r)^-1 mod n
    inv_s_plus_r = mod_inverse(s + r, n)
    
    # 计算 d
    d = ((k - s) % n * inv_s_plus_r) % n
    
    return d

def poc_leak_k():
    """泄露随机数k的漏洞POC验证"""
    print("="*50)
    print("泄露随机数k的漏洞POC验证")
    print("="*50)
    
    # 1. 生成密钥对
    d, P = generate_key_pair()
    print(f"原始私钥 d = {hex(d)}")
    
    # 2. 签名消息（故意使用已知的k）
    message = b"Hello, SM2!"
    k = random.randint(1, n-2)  # 假设这是"泄露"的k
    print(f"使用的随机数 k = {hex(k)}")
    
    # 手动使用已知k进行签名
    point = point_multiply(k, G)
    x1 = point.x
    e = sm3_hash(b'1234567812345678' + message)
    r = (e + x1) % n
    s = (mod_inverse(1 + d, n) * (k - r * d % n) % n) % n
    signature = (r, s)
    print(f"生成的签名 (r,s) = ({hex(r)}, {hex(s)})")
    
    # 3. 假设攻击者获取了签名(r,s)和泄露的随机数k，尝试恢复私钥
    recovered_d = recover_private_key_from_leaked_k(message, signature, k)
    print(f"恢复的私钥 d = {hex(recovered_d)}")
    
    # 4. 验证恢复的私钥是否正确
    assert d == recovered_d, "恢复的私钥不正确！"
    print("私钥恢复成功！原始私钥和恢复的私钥相同。")
    print("\n私钥恢复原理:")
    print("根据SM2签名方程: s = ((1 + d)^-1 * (k - r*d)) mod n")
    print("推导出: d ≡ (k - s) * (s + r)^-1 (mod n)")
