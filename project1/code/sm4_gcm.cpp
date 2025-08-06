#include "sm4_gcm.h"
#include <cstring>
#include <algorithm>

// GCM使用伽罗瓦域GF(2^128)上的运算
// 不可约多项式为x^128 + x^7 + x^2 + x + 1

// 预计算的GF(2^128)乘法表
uint64_t H_TABLE[16][256] = { {0} };
bool h_tables_initialized = false;

// 辅助函数：将128位数据转换为两个64位整数，以便进行高效计算
void block_to_words(const uint8_t* block, uint64_t& high, uint64_t& low) {
    high = 0;
    low = 0;
    for (int i = 0; i < 8; i++) {
        high = (high << 8) | block[i];
        low = (low << 8) | block[i + 8];
    }
}

// 辅助函数：将两个64位整数转换回128位数据块
void words_to_block(uint64_t high, uint64_t low, uint8_t* block) {
    for (int i = 7; i >= 0; i--) {
        block[i] = high & 0xFF;
        high >>= 8;
        block[i + 8] = low & 0xFF;
        low >>= 8;
    }
}

// GF(2^128)上的基本乘法实现
void gf_multiply_basic(const uint8_t* X, const uint8_t* Y, uint8_t* out) {
    uint8_t Z[16] = { 0 };
    uint8_t V[16];
    memcpy(V, Y, 16);

    // 实现"无进位"乘法
    for (int i = 0; i < 16; i++) {
        for (int j = 7; j >= 0; j--) {
            if (X[i] & (1 << j)) {
                // 将V异或到Z中
                for (int k = 0; k < 16; k++) {
                    Z[k] ^= V[k];
                }
            }

            // 将V左移1位
            bool carry = false;
            for (int k = 15; k >= 0; k--) {
                bool next_carry = V[k] & 0x80;
                V[k] = (V[k] << 1) | (carry ? 1 : 0);
                carry = next_carry;
            }

            // 如果有进位，与约化多项式异或
            if (carry) {
                V[15] ^= 0xE1; // 不可约多项式的低位（0xE1 = 11100001）
            }
        }
    }

    memcpy(out, Z, 16);
}

// 初始化用于优化GF(2^128)乘法的预计算表
void init_gf_tables(const uint8_t* H) {
    // 创建表格用于优化GF(2^128)乘法
    uint8_t Z[16] = { 0 };
    uint8_t tmp[16];

    // 初始化字节0（最高有效字节）的表
    for (int i = 0; i < 256; i++) {
        memset(Z, 0, 16);
        Z[0] = i;
        gf_multiply_basic(Z, H, tmp);
        block_to_words(tmp, H_TABLE[0][i], H_TABLE[8][i]);
    }

    // 使用第一个表来构建其余表格
    for (int i = 1; i < 8; i++) {
        for (int j = 0; j < 256; j++) {
            H_TABLE[i][j] = H_TABLE[i - 1][j] >> 8;
            H_TABLE[i][j] |= H_TABLE[i + 7][j] << 56;
            H_TABLE[i + 8][j] = H_TABLE[i + 7][j] >> 8;
        }
    }

    h_tables_initialized = true;
}

// 使用预计算表优化的GF(2^128)乘法
void gf_multiply(const uint8_t* X, const uint8_t* Y, uint8_t* out) {
    if (!h_tables_initialized) {
        // 如果表格未初始化，则使用基本实现
        gf_multiply_basic(X, Y, out);
        return;
    }

    // 使用表格优化的乘法实现
    uint64_t Z_high = 0;
    uint64_t Z_low = 0;

    for (int i = 0; i < 16; i++) {
        Z_high ^= H_TABLE[i][X[i]];
        Z_low ^= H_TABLE[i + 8][X[i]];
    }

    words_to_block(Z_high, Z_low, out);
}

// GCM认证中的GHASH函数
void ghash(const uint8_t* H, const uint8_t* A, size_t A_len, const uint8_t* C, size_t C_len, uint8_t* out) {
    uint8_t X[16] = { 0 }; // 累加器
    uint8_t tmp[16];
    size_t remaining;

    // 处理AAD数据块
    remaining = A_len;
    while (remaining >= 16) {
        for (int i = 0; i < 16; i++) {
            X[i] ^= A[i];
        }
        gf_multiply(X, H, X);
        A += 16;
        remaining -= 16;
    }

    // 处理剩余的AAD字节
    if (remaining > 0) {
        memset(tmp, 0, 16);
        memcpy(tmp, A, remaining);
        for (int i = 0; i < 16; i++) {
            X[i] ^= tmp[i];
        }
        gf_multiply(X, H, X);
    }

    // 处理密文数据块
    remaining = C_len;
    while (remaining >= 16) {
        for (int i = 0; i < 16; i++) {
            X[i] ^= C[i];
        }
        gf_multiply(X, H, X);
        C += 16;
        remaining -= 16;
    }

    // 处理剩余的密文字节
    if (remaining > 0) {
        memset(tmp, 0, 16);
        memcpy(tmp, C, remaining);
        for (int i = 0; i < 16; i++) {
            X[i] ^= tmp[i];
        }
        gf_multiply(X, H, X);
    }

    // 包含A和C的长度（以位为单位）
    uint64_t a_len_bits = A_len * 8;
    uint64_t c_len_bits = C_len * 8;

    memset(tmp, 0, 16);
    // 以大端格式存储长度
    tmp[0] = (a_len_bits >> 56) & 0xFF;
    tmp[1] = (a_len_bits >> 48) & 0xFF;
    tmp[2] = (a_len_bits >> 40) & 0xFF;
    tmp[3] = (a_len_bits >> 32) & 0xFF;
    tmp[4] = (a_len_bits >> 24) & 0xFF;
    tmp[5] = (a_len_bits >> 16) & 0xFF;
    tmp[6] = (a_len_bits >> 8) & 0xFF;
    tmp[7] = a_len_bits & 0xFF;

    tmp[8] = (c_len_bits >> 56) & 0xFF;
    tmp[9] = (c_len_bits >> 48) & 0xFF;
    tmp[10] = (c_len_bits >> 40) & 0xFF;
    tmp[11] = (c_len_bits >> 32) & 0xFF;
    tmp[12] = (c_len_bits >> 24) & 0xFF;
    tmp[13] = (c_len_bits >> 16) & 0xFF;
    tmp[14] = (c_len_bits >> 8) & 0xFF;
    tmp[15] = c_len_bits & 0xFF;

    for (int i = 0; i < 16; i++) {
        X[i] ^= tmp[i];
    }
    gf_multiply(X, H, X);

    memcpy(out, X, 16);
}

// 递增计数器（计数器块的后4个字节）
void increment_counter(uint8_t* counter) {
    uint32_t ctr = (counter[12] << 24) | (counter[13] << 16) | (counter[14] << 8) | counter[15];
    ctr++;
    counter[12] = (ctr >> 24) & 0xFF;
    counter[13] = (ctr >> 16) & 0xFF;
    counter[14] = (ctr >> 8) & 0xFF;
    counter[15] = ctr & 0xFF;
}

// 生成初始计数器块J0
void generate_J0(const uint8_t* iv, size_t iv_len, const uint8_t* H, uint8_t* J0) {
    if (iv_len == 12) {  // 96位IV（推荐）
        memcpy(J0, iv, 12);
        J0[12] = 0;
        J0[13] = 0;
        J0[14] = 0;
        J0[15] = 1;
    }
    else {
        // IV不是96位 - 使用GHASH
        uint8_t tmp[16] = { 0 };
        ghash(H, nullptr, 0, iv, iv_len, J0);

        // 附加IV的长度（以位为单位）
        uint64_t iv_len_bits = iv_len * 8;
        memset(tmp, 0, 16);
        tmp[8] = (iv_len_bits >> 56) & 0xFF;
        tmp[9] = (iv_len_bits >> 48) & 0xFF;
        tmp[10] = (iv_len_bits >> 40) & 0xFF;
        tmp[11] = (iv_len_bits >> 32) & 0xFF;
        tmp[12] = (iv_len_bits >> 24) & 0xFF;
        tmp[13] = (iv_len_bits >> 16) & 0xFF;
        tmp[14] = (iv_len_bits >> 8) & 0xFF;
        tmp[15] = iv_len_bits & 0xFF;

        for (int i = 0; i < 16; i++) {
            J0[i] ^= tmp[i];
        }
        gf_multiply(J0, H, J0);
    }
}

// 生成认证标签
void generate_tag(const uint8_t* J0, const uint8_t* S, const uint32_t* round_keys, uint8_t* tag) {
    uint8_t mask[16];
    sm4_encrypt_ttable(J0, mask, round_keys); // 加密J0

    // 与GHASH输出异或得到标签
    for (int i = 0; i < 16; i++) {
        tag[i] = mask[i] ^ S[i];
    }
}

// 初始化GCM模式，预计算表格
void sm4_gcm_init(const uint8_t* key, uint8_t* H_out) {
    // 生成哈希子密钥H = E_K(0^128)
    uint8_t H[16] = { 0 };
    uint32_t round_keys[SM4_NUM_ROUNDS];

    sm4_set_key(key, round_keys);
    sm4_encrypt_ttable(H, H, round_keys);

    // 初始化GF(2^128)乘法的快速表格
    init_gf_tables(H);

    // 如果需要，返回H
    if (H_out) {
        memcpy(H_out, H, 16);
    }
}

// SM4-GCM加密
bool sm4_gcm_encrypt(
    const uint8_t* key,
    const uint8_t* iv, size_t iv_len,
    const uint8_t* aad, size_t aad_len,
    const uint8_t* plaintext, size_t plaintext_len,
    uint8_t* ciphertext,
    uint8_t* tag
) {
    if (!key || !iv || !tag || (plaintext_len > 0 && (!plaintext || !ciphertext)))
        return false;

    uint32_t round_keys[SM4_NUM_ROUNDS];
    uint8_t H[16] = { 0 };
    uint8_t J0[16];
    uint8_t S[16] = { 0 };
    uint8_t counter[16];
    uint8_t block[16];
    size_t remaining;

    // 初始化密钥
    sm4_set_key(key, round_keys);

    // 生成哈希子密钥H = E_K(0^128)
    sm4_encrypt_ttable(H, H, round_keys);

    // 如果尚未初始化表格，则进行初始化
    if (!h_tables_initialized) {
        init_gf_tables(H);
    }

    // 生成初始计数器块J0
    generate_J0(iv, iv_len, H, J0);

    // 创建加密用的计数器，从J0+1开始
    memcpy(counter, J0, 16);
    increment_counter(counter);

    // 加密明文
    remaining = plaintext_len;
    size_t total_blocks = (plaintext_len + 15) / 16;

    // 处理完整的块
    for (size_t i = 0; i < total_blocks; i++) {
        size_t block_size = (i == total_blocks - 1 && remaining < 16) ? remaining : 16;

        // 加密计数器
        sm4_encrypt_ttable(counter, block, round_keys);

        // 与明文异或得到密文
        for (size_t j = 0; j < block_size; j++) {
            ciphertext[i * 16 + j] = plaintext[i * 16 + j] ^ block[j];
        }

        // 递增计数器
        increment_counter(counter);
        remaining -= block_size;
    }

    // 计算认证标签
    ghash(H, aad, aad_len, ciphertext, plaintext_len, S);
    generate_tag(J0, S, round_keys, tag);

    return true;
}

// SM4-GCM解密和验证
bool sm4_gcm_decrypt(
    const uint8_t* key,
    const uint8_t* iv, size_t iv_len,
    const uint8_t* aad, size_t aad_len,
    const uint8_t* ciphertext, size_t ciphertext_len,
    uint8_t* plaintext,
    const uint8_t* tag
) {
    if (!key || !iv || !tag || (ciphertext_len > 0 && (!ciphertext || !plaintext)))
        return false;

    uint32_t round_keys[SM4_NUM_ROUNDS];
    uint8_t H[16] = { 0 };
    uint8_t J0[16];
    uint8_t S[16] = { 0 };
    uint8_t calculated_tag[16];
    uint8_t counter[16];
    uint8_t block[16];
    size_t remaining;

    // 初始化密钥
    sm4_set_key(key, round_keys);

    // 生成哈希子密钥H = E_K(0^128)
    sm4_encrypt_ttable(H, H, round_keys);

    // 如果尚未初始化表格，则进行初始化
    if (!h_tables_initialized) {
        init_gf_tables(H);
    }

    // 生成初始计数器块J0
    generate_J0(iv, iv_len, H, J0);

    // 计算认证标签用于验证
    ghash(H, aad, aad_len, ciphertext, ciphertext_len, S);
    generate_tag(J0, S, round_keys, calculated_tag);

    // 验证标签
    bool tag_valid = true;
    for (int i = 0; i < 16; i++) {
        if (calculated_tag[i] != tag[i]) {
            tag_valid = false;
        }
    }

    // 如果标签无效，则清除任何部分结果并返回失败
    if (!tag_valid) {
        if (ciphertext_len > 0) {
            memset(plaintext, 0, ciphertext_len);
        }
        return false;
    }

    // 创建解密用的计数器，从J0+1开始
    memcpy(counter, J0, 16);
    increment_counter(counter);

    // 解密密文
    remaining = ciphertext_len;
    size_t total_blocks = (ciphertext_len + 15) / 16;

    // 处理块
    for (size_t i = 0; i < total_blocks; i++) {
        size_t block_size = (i == total_blocks - 1 && remaining < 16) ? remaining : 16;

        // 加密计数器
        sm4_encrypt_ttable(counter, block, round_keys);

        // 与密文异或得到明文
        for (size_t j = 0; j < block_size; j++) {
            plaintext[i * 16 + j] = ciphertext[i * 16 + j] ^ block[j];
        }

        // 递增计数器
        increment_counter(counter);
        remaining -= block_size;
    }

    return true;
}