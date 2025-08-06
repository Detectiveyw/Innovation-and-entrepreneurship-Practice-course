import hashlib
import random  # 添加random导入
from sm2_ec import mod_inverse, point_multiply, point_add, Point, G  # 从sm2_ec导入G
from sm2_params import n  # 只导入n，不导入G

def forge_signature(public_key, message=None):
    """
    伪造ECDSA签名
    public_key: 目标公钥
    message: 想要签名的消息（可选）
    
    返回: (forged_message, forged_signature)，伪造的消息和对应的签名
    """
    # 选择随机数 u 和 v
    u = random.randint(1, n-1)
    v = random.randint(1, n-1)
    
    # 计算点 R = u*G + v*PubKey
    R = point_add(point_multiply(u, G), point_multiply(v, public_key))
    r = R.x % n
    
    # 计算 s = r * v^(-1) mod n
    s = (r * mod_inverse(v, n)) % n
    
    # 计算 e = r * u * v^(-1) mod n
    e = (r * u * mod_inverse(v, n)) % n
    
    # 如果提供了特定消息，我们需要找到一种方式让哈希值等于e
    # 这通常是不可行的，因此这里我们构造消息使其哈希值为e
    if message:
        # 这里应该实现某种预像攻击，但在实践中很难实现
        # 这只是一个示例
        forged_message = message
    else:
        # 将e编码为消息
        forged_message = f"伪造的消息，哈希值为: {hex(e)}".encode()
    
    return forged_message, (r, s)

def verify_ecdsa(message, signature, public_key):
    """
    验证ECDSA签名
    message: 消息
    signature: (r,s)签名值
    public_key: 公钥点
    
    返回: 验证是否通过
    """
    r, s = signature
    
    # 1. 检查签名格式
    if r < 1 or r > n-1 or s < 1 or s > n-1:
        return False
    
    # 2. 计算消息摘要e
    e = int(hashlib.sha256(message).hexdigest(), 16) % n
    
    # 3. 计算 s^(-1) mod n
    s_inv = mod_inverse(s, n)
    
    # 4. 计算 u1 = e * s^(-1) mod n 和 u2 = r * s^(-1) mod n
    u1 = (e * s_inv) % n
    u2 = (r * s_inv) % n
    
    # 5. 计算点 R' = u1*G + u2*PubKey
    R = point_add(point_multiply(u1, G), point_multiply(u2, public_key))
    
    if R.infinity:
        return False
    
    # 6. 验证 R'.x mod n == r
    return (R.x % n) == r

def forge_satoshi_signature():
    """伪造中本聪的数字签名示例"""
    print("="*50)
    print("伪造中本聪的数字签名")
    print("="*50)
    
    # 假设这是中本聪的公钥（这只是一个示例，不是真实的）
    # 在实际情况下，应该使用中本聪的真实公钥
    satoshi_pubkey = Point(
        0x11db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5c,
        0xb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3
    )
    
    # 伪造要签名的消息
    message_to_forge = b"I am Satoshi Nakamoto, the creator of Bitcoin."
    
    # 伪造签名
    forged_message, forged_signature = forge_signature(satoshi_pubkey, message_to_forge)
    
    r, s = forged_signature
    print(f"伪造的消息: {forged_message.decode()}")
    print(f"伪造的签名: (r,s) = ({hex(r)}, {hex(s)})")
    
    # 验证伪造的签名
    is_valid = verify_ecdsa(forged_message, forged_signature, satoshi_pubkey)
    print(f"签名验证结果: {'通过' if is_valid else '未通过'}")
    
    print("\n伪造原理说明:")
    print("1. 选择随机数u和v")
    print("2. 计算R = u*G + v*PubKey")
    print("3. 设置r = R.x mod n")
    print("4. 计算s = r * v^(-1) mod n")
    print("5. 计算e = r * u * v^(-1) mod n，并构造消息使其哈希值为e")
    print("\n这种方法可以伪造任何公钥的签名，但无法为指定消息伪造有效签名")
