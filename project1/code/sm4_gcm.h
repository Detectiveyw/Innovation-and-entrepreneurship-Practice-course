#pragma once
#include "sm4_shared.h"
#include <vector>
#include <cstring>

// SM4-GCM 认证标签的大小（字节）
#define SM4_GCM_TAG_SIZE 16

// GF(2^128)乘法的预计算表
extern uint64_t H_TABLE[16][256];
extern bool h_tables_initialized;

/**
 * 初始化GCM模式，预计算用于GF(2^128)乘法的表格
 * @param key 128位加密密钥
 * @param H_out 哈希子密钥H（可选输出参数）
 */
void sm4_gcm_init(const uint8_t* key, uint8_t* H_out = nullptr);

/**
 * 执行SM4-GCM加密
 * @param key 128位加密密钥
 * @param iv 初始化向量（nonce）
 * @param iv_len IV的字节长度（推荐12字节）
 * @param aad 附加认证数据
 * @param aad_len AAD的字节长度
 * @param plaintext 待加密的明文
 * @param plaintext_len 明文的字节长度
 * @param ciphertext 密文输出缓冲区（至少需要plaintext_len字节）
 * @param tag 认证标签输出缓冲区（必须为SM4_GCM_TAG_SIZE字节）
 * @return 如果加密成功则返回true
 */
bool sm4_gcm_encrypt(
    const uint8_t* key,
    const uint8_t* iv, size_t iv_len,
    const uint8_t* aad, size_t aad_len,
    const uint8_t* plaintext, size_t plaintext_len,
    uint8_t* ciphertext,
    uint8_t* tag);

/**
 * 执行SM4-GCM解密和验证
 * @param key 128位加密密钥
 * @param iv 初始化向量（nonce）
 * @param iv_len IV的字节长度（推荐12字节）
 * @param aad 附加认证数据
 * @param aad_len AAD的字节长度
 * @param ciphertext 待解密的密文
 * @param ciphertext_len 密文的字节长度
 * @param plaintext 明文输出缓冲区（至少需要ciphertext_len字节）
 * @param tag 待验证的认证标签
 * @return 如果解密和标签验证成功则返回true
 */
bool sm4_gcm_decrypt(
    const uint8_t* key,
    const uint8_t* iv, size_t iv_len,
    const uint8_t* aad, size_t aad_len,
    const uint8_t* ciphertext, size_t ciphertext_len,
    uint8_t* plaintext,
    const uint8_t* tag);

// 内部函数（用于测试和调试）

/**
 * 执行GCM模式中的GHASH操作
 * @param H 哈希子密钥
 * @param A 附加认证数据
 * @param A_len AAD的字节长度
 * @param C 密文
 * @param C_len 密文的字节长度
 * @param out GHASH结果的输出缓冲区（16字节）
 */
void ghash(
    const uint8_t* H,
    const uint8_t* A, size_t A_len,
    const uint8_t* C, size_t C_len,
    uint8_t* out);

/**
 * 使用预计算表执行GF(2^128)域上的乘法
 * @param X 第一个128位输入块
 * @param Y 第二个128位输入块
 * @param out 128位输出块
 */
void gf_multiply(const uint8_t* X, const uint8_t* Y, uint8_t* out);

/**
 * 增加128位大端格式的计数器值
 * @param counter 要递增的计数器块
 */
void increment_counter(uint8_t* counter);

/**
 * 根据GCM规范，从IV生成初始计数器块J0
 * @param iv 初始化向量
 * @param iv_len IV的字节长度
 * @param H 哈希子密钥
 * @param J0 初始计数器块的输出缓冲区（16字节）
 */
void generate_J0(const uint8_t* iv, size_t iv_len, const uint8_t* H, uint8_t* J0);

/**
 * 构造最终的认证标签
 * @param J0 初始计数器块
 * @param S GHASH输出
 * @param round_keys SM4轮密钥
 * @param tag 标签的输出缓冲区（16字节）
 */
void generate_tag(const uint8_t* J0, const uint8_t* S, const uint32_t* round_keys, uint8_t* tag);

/**
 * 初始化用于优化GF(2^128)乘法的预计算表
 * @param H 哈希子密钥H
 */
void init_gf_tables(const uint8_t* H);

/**
 * 基本的GF(2^128)乘法实现（用于表初始化）
 * @param X 第一个128位输入块
 * @param Y 第二个128位输入块
 * @param out 128位输出块
 */
void gf_multiply_basic(const uint8_t * X, const uint8_t * Y, uint8_t * out); 