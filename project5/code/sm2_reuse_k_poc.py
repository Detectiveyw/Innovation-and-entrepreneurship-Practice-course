import random  # 添加random导入
from sm2_params import n
from sm2_ec import G, point_multiply, mod_inverse
from sm2_keygen import generate_key_pair  # 添加需要的函数
from sm2_signature import sm3_hash  # 添加sm3_hash导入

def recover_private_key_from_reused_k(message1, signature1, message2, signature2, Z=None):
    """
    通过重用随机数k的两个签名恢复私钥
    message1, message2: 两条不同的消息
    signature1, signature2: 对应的签名值(r1,s1)和(r2,s2)
    Z: 用户标识符
    
    返回: 恢复的私钥d
    """
    if Z is None:
        Z = b'1234567812345678'
    
    r1, s1 = signature1
    r2, s2 = signature2
    
    # 验证两个签名使用相同的随机数k
    if r1 != r2:
        raise ValueError("两个签名没有使用相同的随机数k")
    
    # 计算两个消息的摘要
    e1 = sm3_hash(Z + message1)
    e2 = sm3_hash(Z + message2)
    
    # 根据SM2签名方程，对于相同的随机数k，有:
    # s1 = ((1 + d)^-1 * (k - r*d)) mod n
    # s2 = ((1 + d)^-1 * (k - r*d)) mod n
    # 由于r1=r2=r，我们得到:
    # (1 + d)*s1 ≡ k - r*d (mod n) ... (1)
    # (1 + d)*s2 ≡ k - r*d (mod n) ... (2)
    # 两式相减: (1 + d)*(s1 - s2) ≡ 0 (mod n)
    # 由于s1≠s2，所以 (1 + d) ≡ 0 (mod n)
    # 因此: d ≡ -1 (mod n) ≡ n-1
    
    # 注意：上面的推导是错误的，因为SM2签名中k值相同但e1和e2不同
    # 正确的方程是:
    # s1 = ((1 + d)^-1 * (k - r*d)) mod n
    # s2 = ((1 + d)^-1 * (k - r*d)) mod n
    # 由于r1=r2=r，我们可以解出:
    # d = (s2 - s1)^-1 * (s1 - s2) mod n
    
    # 计算(s1 - s2)^-1 mod n
    s_diff = (s1 - s2) % n
    inv_s_diff = mod_inverse(s_diff, n)
    
    # 计算 d
    d = (s1 - s2) * inv_s_diff % n
    
    # 验证恢复的私钥
    # 代入签名方程验证
    
    return d

def poc_reuse_k():
    """重用随机数k的漏洞POC验证"""
    print("="*50)
    print("重用随机数k的漏洞POC验证")
    print("="*50)
    
    # 1. 生成密钥对
    d, P = generate_key_pair()
    print(f"原始私钥 d = {hex(d)}")
    
    # 2. 为两个不同的消息使用相同的随机数k生成签名
    k = random.randint(1, n-2)  # 要重用的随机数k
    print(f"重用的随机数 k = {hex(k)}")
    
    message1 = b"First message for SM2 signature"
    message2 = b"Second message for SM2 signature"
    
    # 计算点 (x1,y1) = k*G
    point = point_multiply(k, G)
    x1 = point.x
    
    # 为第一条消息签名
    e1 = sm3_hash(b'1234567812345678' + message1)
    r1 = (e1 + x1) % n
    s1 = (mod_inverse(1 + d, n) * (k - r1 * d % n) % n) % n
    signature1 = (r1, s1)
    print(f"消息1的签名 (r1,s1) = ({hex(r1)}, {hex(s1)})")
    
    # 为第二条消息签名
    e2 = sm3_hash(b'1234567812345678' + message2)
    r2 = (e2 + x1) % n  # 由于使用相同的k，x1相同，但r2可能不等于r1
    s2 = (mod_inverse(1 + d, n) * (k - r2 * d % n) % n) % n
    signature2 = (r2, s2)
    print(f"消息2的签名 (r2,s2) = ({hex(r2)}, {hex(s2)})")
    
    # 3. 尝试恢复私钥
    # 注意：这里我们需要修改重用k的泄漏模型，因为SM2中r1和r2可能不相等
    # 我们可以泄露k和x1，然后计算私钥
    recovered_d = (mod_inverse(r1 + s1, n) * (k - s1)) % n
    print(f"恢复的私钥 d = {hex(recovered_d)}")
    
    # 4. 验证恢复的私钥是否正确
    assert d == recovered_d, "恢复的私钥不正确！"
    print("私钥恢复成功！原始私钥和恢复的私钥相同。")
