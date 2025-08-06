# -*- coding: utf-8 -*-

import hashlib
import os
from typing import Set, List, Tuple

# 导入 tinyec 库，它让我们能直接进行椭圆曲线点运算
from tinyec import registry
from tinyec.ec import Point

# --- 全局配置 ---

# 1. 定义使用的椭圆曲线
# 我们从 tinyec 的注册表中获取标准曲线 'secp256r1' (NIST P-256)
CURVE = registry.get_curve('secp256r1')

# 2. 定义哈希函数 H1 (此函数不变)
def h1(username: str, password: str) -> bytes:
    """
    哈希函数 H1: 将用户名和密码组合并哈希，作为协议的输入 x。
    """
    username_bytes = username.encode('utf-8')
    password_bytes = password.encode('utf-8')
    hasher = hashlib.sha256()
    hasher.update(b"username:" + username_bytes)
    hasher.update(b"password:" + password_bytes)
    return hasher.digest()

# 3. 定义哈希函数 H2 (Hash-to-Curve)
# H2 的实现针对 tinyec 库进行了修改。
def h2_hash_to_curve(data: bytes) -> Point:
    """
    哈希函数 H2: 将字节串 data 映射到椭圆曲线 CURVE 上的一个点。
    现在返回一个 tinyec 的 Point 对象。
    """
    # tinyec 提供了直接从哈希值生成点的方法，更简单健壮
    # 我们只需要确保哈希的输出（整数）在曲线的域内
    while True:
        # 通过哈希 data 生成候选的 x 坐标
        x_bytes = hashlib.sha256(data).digest()
        x = int.from_bytes(x_bytes, 'big')

        # 尝试在曲线上找到与 x 对应的点
        # 曲线方程: y^2 = x^3 + ax + b (mod p)
        # 我们需要计算右边 y_squared = (x^3 + a*x + b) mod p
        y_sq = (pow(x, 3, CURVE.field.p) + CURVE.a * x + CURVE.b) % CURVE.field.p
        
        # 计算模 p 的平方根来找到 y
        # 注意：不是所有数都有模平方根。这里使用 Tonelli-Shanks 或 Cipolla's 算法
        # 为了简化，tinyec 内部可能处理了，但一个简单的方法是检查它是否是二次剩余
        if pow(y_sq, (CURVE.field.p - 1) // 2, CURVE.field.p) == 1:
            # 如果是二次剩余，我们可以计算出 y
            y = pow(y_sq, (CURVE.field.p + 1) // 4, CURVE.field.p) # 适用于 p = 3 (mod 4)
            
            # 创建并返回点对象
            return Point(CURVE, x, y)
        
        # 如果找不到点，就附加一个字节再次哈希（Try and Increment）
        data += b'\x00'

# 4. 序列化和反序列化函数
# 我们需要一种方法将 tinyec 的点对象转换为字节串以便网络传输，反之亦然。
def point_to_bytes(point: Point) -> bytes:
    """将 tinyec Point 对象序列化为字节串。"""
    # 我们简单地将 x 和 y 坐标拼接起来
    coord_size = (CURVE.field.n.bit_length() + 7) // 8
    return point.x.to_bytes(coord_size, 'big') + point.y.to_bytes(coord_size, 'big')

def bytes_to_point(b: bytes) -> Point:
    """从字节串反序列化为 tinyec Point 对象。"""
    coord_size = (CURVE.field.n.bit_length() + 7) // 8
    x = int.from_bytes(b[:coord_size], 'big')
    y = int.from_bytes(b[coord_size:], 'big')
    return Point(CURVE, x, y)

# 5. 定义前缀长度 (此部分不变)
PREFIX_LENGTH_BYTES = 4


class Server:
    def __init__(self, breached_credentials: Set[Tuple[str, str]]):
        print("--- [服务器] 初始化开始 ---")
        # 1. 生成服务器的秘密密钥 k
        # 在 tinyec 中，密钥 k 就是一个在曲线阶范围内的随机整数
        self._k = int.from_bytes(os.urandom(32), 'big') % CURVE.field.n
        print(f"[服务器] 秘密密钥 k 已生成。")
        
        self._breached_prf_values = {}
        print(f"[服务器] 正在预处理 {len(breached_credentials)} 条泄露凭据...")

        for username, password in breached_credentials:
            y = h1(username, password)
            h2_y = h2_hash_to_curve(y)
            
            # 计算 PRF 值: v_y = k * H2(y)
            # 使用 tinyec，点乘法可以直接用 * 操作符，非常直观！
            v_y_point = self._k * h2_y
            
            v_y_bytes = point_to_bytes(v_y_point)
            prefix = v_y_bytes[:PREFIX_LENGTH_BYTES]
            
            if prefix not in self._breached_prf_values:
                self._breached_prf_values[prefix] = []
            self._breached_prf_values[prefix].append(v_y_bytes)

        print(f"[服务器] 预处理完成。生成了 {len(self._breached_prf_values)} 个唯一的前缀。")
        print("--- [服务器] 初始化结束 ---\n")

    def get_breached_prf_prefixes(self) -> List[bytes]:
        print("[服务器] 收到客户端请求，发送所有泄露凭据的PRF值前缀列表。")
        return list(self._breached_prf_values.keys())

    def handle_blinded_request(self, T_bytes: bytes) -> bytes:
        print("[服务器] 收到客户端的盲化请求 T。")
        # 1. 从字节串恢复出点 T
        T_point = bytes_to_point(T_bytes)
        
        # 2. 计算 Z = k * T，这里的乘法现在可以正确工作了
        Z_point = self._k * T_point
        
        # 3. 将结果点 Z 转换回字节串
        Z_bytes = point_to_bytes(Z_point)
        print("[服务器] 计算完成 Z = k * T，并将其返回给客户端。")
        return Z_bytes

    def get_full_hashes_for_prefix(self, prefix: bytes) -> List[bytes]:
        print(f"[服务器] 收到客户端对前缀 {prefix.hex()} 的请求，返回对应的完整哈希。")
        return self._breached_prf_values.get(prefix, [])


class Client:
    def __init__(self, username: str, password: str):
        self.username = username
        self.password = password
        print(f"--- [客户端] 初始化，准备检查凭据 (用户: '{self.username}') ---\n")

    def check_password_leak(self, server: Server) -> bool:
        print(f"[客户端] 开始检查用户 '{self.username}' 的密码。")
        
        # === 协议第一步: 客户端进行盲化 ===
        x = h1(self.username, self.password)
        print(f"[客户端] 1. 计算凭据哈希 H1(u, p) = {x.hex()}")

        P = h2_hash_to_curve(x)
        print(f"[客户端] 2. 将哈希映射到曲线点 P")

        # 盲化因子 t 是一个随机整数
        t = int.from_bytes(os.urandom(32), 'big') % CURVE.field.n
        print(f"[客户端] 3. 生成随机盲化因子 t")

        # 计算盲化点 T = t * P，现在可以正确工作
        T_point = t * P
        T_bytes = point_to_bytes(T_point)
        print(f"[客户端] 4. 计算盲化点 T = t * P，准备发送给服务器。")

        # === 协议第二步: 与服务器交互 ===
        print("\n[客户端] --- 开始与服务器通信 ---")
        Z_bytes = server.handle_blinded_request(T_bytes)
        print("[客户端] --- 通信结束 ---\n")
        
        # === 协议第三步: 客户端去盲并检查 ===
        # 计算 t 的模逆元，注意模数是曲线的阶 CURVE.field.n
        t_inv = pow(t, -1, CURVE.field.n)
        print(f"[客户端] 5. 计算 t 的逆元 t_inv")

        Z_point = bytes_to_point(Z_bytes)
        
        # 去盲，计算 V = t_inv * Z
        V_point = t_inv * Z_point
        V_bytes = point_to_bytes(V_point)
        print(f"[客户端] 6. 去盲得到 PRF 值 V = k*H2(x) = {V_bytes.hex()}")

        leaked_prefixes = server.get_breached_prf_prefixes()
        print(f"[客户端] 7. 从服务器获取了 {len(leaked_prefixes)} 个泄露数据的前缀。")

        my_prefix = V_bytes[:PREFIX_LENGTH_BYTES]
        print(f"[客户端] 8. 我计算出的 V 的前缀是: {my_prefix.hex()}")

        if my_prefix in leaked_prefixes:
            print(f"[客户端] 9. 警告! 前缀匹配成功。可能存在泄露，需要进一步确认。")
            full_hashes_for_prefix = server.get_full_hashes_for_prefix(my_prefix)
            if V_bytes in full_hashes_for_prefix:
                print(f"[客户端] 10. 最终确认: 完整的 PRF 值匹配成功。")
                print(f"--- [结论] 凭据 (用户: '{self.username}') 已经泄露! ---\n")
                return True
            else:
                print(f"[客户端] 10. 最终确认: 完整的 PRF 值不匹配。这是一次前缀碰撞，凭据安全。")
                print(f"--- [结论] 凭据 (用户: '{self.username}') 是安全的。 ---\n")
                return False
        else:
            print(f"[客户端] 9. 前缀不匹配。")
            print(f"--- [结论] 凭据 (用户: '{self.username}') 是安全的。 ---\n")
            return False

# --- 主程序：模拟运行 (不变) ---
if __name__ == "__main__":
    breached_database = {
        ("alice", "123456"),
        ("bob", "password"),
        ("charlie", "qwerty"),
        ("david", "google-sucks"),
    }

    server = Server(breached_database)

    print("="*40)
    print("场景1: 检查一个已泄露的密码 ('alice', '123456')")
    print("="*40)
    client_leaked = Client("alice", "123456")
    is_leaked_1 = client_leaked.check_password_leak(server)
    assert is_leaked_1 is True

    print("="*40)
    print("场景2: 检查一个安全的密码 ('eve', 'MySecurePa$$w0rd')")
    print("="*40)
    client_safe = Client("eve", "MySecurePa$$w0rd")
    is_leaked_2 = client_safe.check_password_leak(server)
    assert is_leaked_2 is False
