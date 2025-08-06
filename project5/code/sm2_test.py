#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SM2算法验证测试脚本
作者: Detectiveyw
日期: 2025-07-30
"""

import os
import sys
import random
import hashlib
from sm2_params import p, a, b, n, Gx, Gy
from sm2_ec import Point, point_add, point_multiply, point_double, mod_inverse, is_on_curve, G
from sm2_keygen import generate_key_pair, compress_public_key, decompress_public_key
from sm2_signature import sm3_hash, sign, verify
from sm2_encryption import encrypt, decrypt, kdf
from sm2_leak_k_poc import recover_private_key_from_leaked_k, poc_leak_k
from sm2_reuse_k_poc import poc_reuse_k
# 注意: sm2_ecdsa_same_key_poc 模块中的示例代码未完全实现，实际运行时需要先完成该模块
# from sm2_ecdsa_same_key_poc import poc_sm2_ecdsa_same_key
from forge_satoshi_signature import forge_satoshi_signature

def clear_screen():
    """清除屏幕"""
    os.system('cls' if os.name == 'nt' else 'clear')

def print_header(title):
    """打印标题"""
    print("="*60)
    print(f"{title:^60}")
    print("="*60)

def pause():
    """暂停并等待用户输入"""
    input("\n按回车键继续...")

def test_basic_operations():
    """测试基本的椭圆曲线操作"""
    print_header("基本椭圆曲线操作测试")
    
    # 验证基点G在曲线上
    print(f"基点G = ({hex(Gx)}, {hex(Gy)})")
    print(f"G在曲线上: {is_on_curve(G)}")
    
    # 测试点加法
    P = point_multiply(3, G)
    Q = point_multiply(5, G)
    R = point_add(P, Q)
    
    print(f"3G = ({hex(P.x)}, {hex(P.y)})")
    print(f"5G = ({hex(Q.x)}, {hex(Q.y)})")
    print(f"3G + 5G = ({hex(R.x)}, {hex(R.y)})")
    
    # 验证点加法的结果
    R_check = point_multiply(8, G)
    print(f"8G = ({hex(R_check.x)}, {hex(R_check.y)})")
    print(f"3G + 5G == 8G: {R == R_check}")
    
    return True

def test_key_generation():
    """测试密钥生成和压缩"""
    print_header("密钥生成与压缩测试")
    
    try:
        # 生成密钥对
        private_key, public_key = generate_key_pair()
        print(f"私钥 d = {hex(private_key)}")
        print(f"公钥 P = ({hex(public_key.x)}, {hex(public_key.y)})")
        
        # 验证生成的公钥是否在曲线上
        if not is_on_curve(public_key):
            print("警告: 生成的公钥点不在曲线上！")
            return False
        
        # 测试公钥压缩
        try:
            compressed = compress_public_key(public_key)
            print(f"压缩公钥: {compressed.hex()}")
        except Exception as e:
            print(f"公钥压缩失败: {e}")
            return False
        
        # 测试公钥解压缩
        try:
            decompressed = decompress_public_key(compressed)
            print(f"解压缩公钥: ({hex(decompressed.x)}, {hex(decompressed.y)})")
        except Exception as e:
            print(f"公钥解压缩失败: {e}")
            return False
        
        # 验证解压缩结果
        print(f"压缩/解压缩一致性: {public_key == decompressed}")
        if public_key != decompressed:
            print("警告: 压缩和解压缩后的公钥不匹配！")
            return False
        
        return private_key, public_key
    
    except Exception as e:
        print(f"密钥生成测试失败: {e}")
        import traceback
        traceback.print_exc()
        return False
        

def test_signature():
    """测试签名和验证"""
    print_header("签名与验证测试")
    
    # 生成密钥对
    private_key, public_key = generate_key_pair()
    print(f"私钥 d = {hex(private_key)}")
    print(f"公钥 P = ({hex(public_key.x)}, {hex(public_key.y)})")
    
    # 准备消息
    message = b"Hello, SM2 signature!"
    print(f"消息: {message.decode()}")
    
    # 签名
    signature = sign(message, private_key)
    r, s = signature
    print(f"签名 (r, s) = ({hex(r)}, {hex(s)})")
    
    # 验证签名
    is_valid = verify(message, signature, public_key)
    print(f"签名验证结果: {'成功' if is_valid else '失败'}")
    
    # 篡改消息测试
    tampered_message = b"Hello, tampered message!"
    is_valid = verify(tampered_message, signature, public_key)
    print(f"篡改消息验证结果: {'成功' if is_valid else '失败'} (预期为失败)")
    
    return private_key, public_key, message, signature

def test_encryption():
    """测试加密和解密"""
    print_header("加密与解密测试")
    
    # 生成密钥对
    private_key, public_key = generate_key_pair()
    print(f"私钥 d = {hex(private_key)}")
    print(f"公钥 P = ({hex(public_key.x)}, {hex(public_key.y)})")
    
    # 准备明文
    message = b"This is a secret message for SM2 encryption test!"
    print(f"原始明文: {message.decode()}")
    
    # 加密
    ciphertext = encrypt(message, public_key)
    print(f"密文长度: {len(ciphertext)} 字节")
    print(f"密文(前32字节): {ciphertext[:32].hex()}")
    
    # 解密
    try:
        decrypted = decrypt(ciphertext, private_key)
        print(f"解密结果: {decrypted.decode()}")
        print(f"解密是否成功: {message == decrypted}")
    except Exception as e:
        print(f"解密失败: {e}")
    
    return True

def main():
    """主函数"""
    while True:
        clear_screen()
        print_header("SM2算法测试与验证")
        print("\n请选择要运行的测试:")
        print("1. 基本椭圆曲线操作测试")
        print("2. 密钥生成与压缩测试")
        print("3. 签名与验证测试")
        print("4. 加密与解密测试")
        print("5. 泄露随机数k的漏洞验证")
        print("6. 重用随机数k的漏洞验证")
        print("7. 伪造中本聪的数字签名")
        print("0. 退出程序")
        
        choice = input("\n请输入选择 [0-7]: ")
        
        if choice == '0':
            print("谢谢使用，再见！")
            sys.exit(0)
        
        clear_screen()
        
        if choice == '1':
            test_basic_operations()
        elif choice == '2':
            test_key_generation()
        elif choice == '3':
            test_signature()
        elif choice == '4':
            test_encryption()
        elif choice == '5':
            poc_leak_k()
        elif choice == '6':
            poc_reuse_k()
        elif choice == '7':
            forge_satoshi_signature()
        else:
            print("无效的选择，请重新输入！")
            continue
        
        pause()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n程序被用户中断")
        sys.exit(0)
    except Exception as e:
        print(f"发生错误: {e}")
        sys.exit(1)
