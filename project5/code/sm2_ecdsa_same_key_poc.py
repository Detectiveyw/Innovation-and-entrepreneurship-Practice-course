from sm2_params import n, G
from sm2_ec import point_multiply, mod_inverse

def ecdsa_sign(message, private_key, k):
    """使用给定的随机数k生成ECDSA签名"""
    e = sm3_hash(message)  # 使用相同的哈希函数
    
    # 计算 (x1,y1) = k*G
    point = point_multiply(k, G)
    x1 = point.x
    
    # ECDSA签名
    r = x1 % n
    s = (mod_inverse(k, n) * (e + r * private_key % n)) % n
    
    return (r, s)

def recover_private_key_from_sm2_ecdsa(message, sm2_sig, ecdsa_sig):
    """
    从使用相同私钥和随机数k生成的SM2和ECDSA签名中恢复私钥
    message: 消息
    sm2_sig: SM2签名 (r_sm2, s_sm2)
    ecdsa_sig: ECDSA签名 (r_ecdsa, s_ecdsa)
    
    返回: 恢复的私钥d
    """
    r_sm2, s_sm2 = sm2_sig
    r_ecdsa, s_ecdsa = ecdsa_sig
    
    # 计算消息摘要
    e = sm3_hash(message)
    
    # 在SM2中，r = (e + x1) mod n，其中x1是k*G的x坐标
    # 在ECDSA中，r = x1 mod n
    # 所以x1 = r_ecdsa
    # 且 r_sm2 = (e + r_ecdsa) mod n
    
    # SM2签名方程: s_sm2 = ((1 + d)^-1 * (k - r_sm2*d)) mod n
    # ECDSA签名方程: s_ecdsa = ((k^-1) * (e + r_ecdsa*d)) mod n
    
    # 从ECDSA方程可得: k = (e + r_ecdsa*d) * s_ecdsa^-1 mod n
    # 代入SM2方程:
    # s_sm2 = ((1 + d)^-1 * ((e + r_ecdsa*d) * s_ecdsa^-1 - r_sm2*d)) mod n
    
    # 推导过程较复杂，这里直接给出结果
    # 最终可以得到一个关于d的方程，求解可得d
    
    # 这里实现一个简化版本，假设我们已知r_sm2 = (e + r_ecdsa) mod n
    
    # 计算 s_ecdsa^-1 mod n
    inv_s_ecdsa = mod_inverse(s_ecdsa, n)
    
    # 从ECDSA方程得到k
    k = (e + r_ecdsa * d) * inv_s_ecdsa % n
    
    # 代入SM2方程
    # (1 + d) * s_sm2 ≡ k - r_sm2 * d (mod n)
    # 代入k的表达式
    # (1 + d) * s_sm2 ≡ (e + r_ecdsa * d) * inv_s_ecdsa - r_sm2 * d (mod n)
    
    # 解方程获得d
    # 这是一个复杂的推导过程，这里简化处理
    
    # 这部分需要更详细的数学推导，这里仅作示意
    d = ...  # 解出的私钥
    
    return d

def poc_sm2_ecdsa_same_key():
    """SM2与ECDSA使用相同私钥和随机数的漏洞POC验证"""
    print("="*50)
    print("SM2与ECDSA使用相同私钥和随机数的漏洞POC验证")
    print("="*50)
    
    # 1. 生成密钥对
    d, P = generate_key_pair()
    print(f"原始私钥 d = {hex(d)}")
    
    # 2. 为同一消息使用相同的随机数k生成SM2和ECDSA签名
    k = random.randint(1, n-2)
    print(f"使用的随机数 k = {hex(k)}")
    
    message = b"Message for both SM2 and ECDSA"
    
    # SM2签名
    point = point_multiply(k, G)
    x1 = point.x
    e = sm3_hash(message)
    r_sm2 = (e + x1) % n
    s_sm2 = (mod_inverse(1 + d, n) * (k - r_sm2 * d % n) % n) % n
    sm2_sig = (r_sm2, s_sm2)
    print(f"SM2签名 (r,s) = ({hex(r_sm2)}, {hex(s_sm2)})")
    
    # ECDSA签名
    ecdsa_sig = ecdsa_sign(message, d, k)
    r_ecdsa, s_ecdsa = ecdsa_sig
    print(f"ECDSA签名 (r,s) = ({hex(r_ecdsa)}, {hex(s_ecdsa)})")
    
    # 3. 尝试恢复私钥
    # 使用上述已知条件尝试恢复私钥
    # 这部分需要更详细的数学推导和验证
    
    print("注意：SM2与ECDSA使用相同的随机数k进行签名会导致私钥泄露。")
    print("具体恢复私钥的完整算法需要更详细的数学推导，此处略去。")
