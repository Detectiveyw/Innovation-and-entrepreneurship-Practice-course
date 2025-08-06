#include "sm3.hpp"
#include <cstring>
#include <stdexcept>

// --------------------------- 辅助宏和函数 ---------------------------

// 大端字节序转换
#ifndef GET_UINT32_BE
#define GET_UINT32_BE(n, b, i)                                  \
{                                                               \
    (n) = ( (uint32_t) (b)[(i)    ] << 24 )                      \
        | ( (uint32_t) (b)[(i) + 1] << 16 )                      \
        | ( (uint32_t) (b)[(i) + 2] <<  8 )                      \
        | ( (uint32_t) (b)[(i) + 3]       );                     \
}
#endif

#ifndef PUT_UINT32_BE
#define PUT_UINT32_BE(n, b, i)                                  \
{                                                               \
    (b)[(i)    ] = (uint8_t) ( (n) >> 24 );                      \
    (b)[(i) + 1] = (uint8_t) ( (n) >> 16 );                      \
    (b)[(i) + 2] = (uint8_t) ( (n) >>  8 );                      \
    (b)[(i) + 3] = (uint8_t) ( (n)       );                      \
}
#endif

// 循环左移
#define ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

// SM3布尔函数
#define FF_00_15(X, Y, Z) ((X) ^ (Y) ^ (Z))
#define FF_16_63(X, Y, Z) (((X) & (Y)) | ((X) & (Z)) | ((Y) & (Z)))

#define GG_00_15(X, Y, Z) ((X) ^ (Y) ^ (Z))
#define GG_16_63(X, Y, Z) (((X) & (Y)) | ((~(X)) & (Z)))

// SM3置换函数
#define P0(X) ((X) ^ ROTL((X), 9) ^ ROTL((X), 17))
#define P1(X) ((X) ^ ROTL((X), 15) ^ ROTL((X), 23))

// SM3初始IV值
static const uint32_t sm3_iv[8] = {
    0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
    0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E
};

// SM3常量Tj
static const uint32_t T_00_15 = 0x79CC4519;
static const uint32_t T_16_63 = 0x7A879D8A;

// --------------------------- 类实现 ---------------------------

SM3::SM3(bool use_optimized) : use_optimized_compress(use_optimized) {
    init();
}

void SM3::init() {
    memcpy(state, sm3_iv, sizeof(sm3_iv));
    total_len = 0;
    buflen = 0;
    memset(buffer, 0, SM3_BLOCK_SIZE);
}

void SM3::update(const uint8_t* data, size_t len) {
    if (!data || len == 0) return;

    total_len += len;
    const uint8_t *p = data;
    size_t left = len;

    if (buflen > 0) {
        size_t needed = SM3_BLOCK_SIZE - buflen;
        if (left >= needed) {
            memcpy(buffer + buflen, p, needed);
            use_optimized_compress ? compress_optimized(buffer) : compress_basic(buffer);
            p += needed;
            left -= needed;
            buflen = 0;
        } else {
            memcpy(buffer + buflen, p, left);
            buflen += left;
            return;
        }
    }

    while (left >= SM3_BLOCK_SIZE) {
        use_optimized_compress ? compress_optimized(p) : compress_basic(p);
        p += SM3_BLOCK_SIZE;
        left -= SM3_BLOCK_SIZE;
    }

    if (left > 0) {
        memcpy(buffer, p, left);
        buflen = left;
    }
}

void SM3::update(const std::vector<uint8_t>& data) {
    update(data.data(), data.size());
}

void SM3::final(uint8_t digest[SM3_DIGEST_LENGTH]) {
    uint8_t final_block[SM3_BLOCK_SIZE];
    uint64_t total_bits = total_len * 8;

    memcpy(final_block, buffer, buflen);
    final_block[buflen++] = 0x80;

    if (buflen > SM3_BLOCK_SIZE - 8) {
        memset(final_block + buflen, 0, SM3_BLOCK_SIZE - buflen);
        use_optimized_compress ? compress_optimized(final_block) : compress_basic(final_block);
        memset(final_block, 0, SM3_BLOCK_SIZE);
    } else {
        memset(final_block + buflen, 0, SM3_BLOCK_SIZE - buflen);
    }

    PUT_UINT32_BE((uint32_t)(total_bits >> 32), final_block, SM3_BLOCK_SIZE - 8);
    PUT_UINT32_BE((uint32_t)(total_bits), final_block, SM3_BLOCK_SIZE - 4);

    use_optimized_compress ? compress_optimized(final_block) : compress_basic(final_block);
    
    for (int i = 0; i < 8; i++) {
        PUT_UINT32_BE(state[i], digest, i * 4);
    }

    init(); // 重置状态以便复用
}

std::vector<uint8_t> SM3::final() {
    std::vector<uint8_t> digest(SM3_DIGEST_LENGTH);
    final(digest.data());
    return digest;
}


void SM3::hash(const std::vector<uint8_t>& data, uint8_t digest[SM3_DIGEST_LENGTH], bool use_optimized) {
    SM3 sm3(use_optimized);
    sm3.update(data);
    sm3.final(digest);
}

std::vector<uint8_t> SM3::hash(const std::vector<uint8_t>& data, bool use_optimized) {
    SM3 sm3(use_optimized);
    sm3.update(data);
    return sm3.final();
}

/**
 * @brief [a部分] SM3基础压缩函数。
 * 参考付勇老师PPT中的标准实现思路。
 * 该版本为便于理解，先完成消息扩展，再进行64轮迭代压缩。
 */
void SM3::compress_basic(const uint8_t block[SM3_BLOCK_SIZE]) {
    uint32_t W[68], W_prime[64];
    uint32_t A, B, C, D, E, F, G, H;
    uint32_t SS1, SS2, TT1, TT2;

    // 1. 消息扩展 (Message Expansion)
    for (int j = 0; j < 16; j++) {
        GET_UINT32_BE(W[j], block, j * 4);
    }
    for (int j = 16; j < 68; j++) {
        W[j] = P1(W[j - 16] ^ W[j - 9] ^ ROTL(W[j - 3], 15)) ^ ROTL(W[j - 13], 7) ^ W[j - 6];
    }
    for (int j = 0; j < 64; j++) {
        W_prime[j] = W[j] ^ W[j + 4];
    }

    // 2. 迭代压缩 (Iterative Compression)
    A = state[0]; B = state[1]; C = state[2]; D = state[3];
    E = state[4]; F = state[5]; G = state[6]; H = state[7];

    for (int j = 0; j < 64; j++) {
        SS1 = ROTL(ROTL(A, 12) + E + ROTL((j < 16) ? T_00_15 : T_16_63, j), 7);
        SS2 = SS1 ^ ROTL(A, 12);
        
        TT1 = (j < 16) ? FF_00_15(A, B, C) + D + SS2 + W_prime[j] : FF_16_63(A, B, C) + D + SS2 + W_prime[j];
        TT2 = (j < 16) ? GG_00_15(E, F, G) + H + SS1 + W[j] : GG_16_63(E, F, G) + H + SS1 + W[j];

        D = C;
        C = ROTL(B, 9);
        B = A;
        A = TT1;
        H = G;
        G = ROTL(F, 19);
        F = E;
        E = P0(TT2);
    }

    // 3. 更新状态
    state[0] ^= A; state[1] ^= B; state[2] ^= C; state[3] ^= D;
    state[4] ^= E; state[5] ^= F; state[6] ^= G; state[7] ^= H;
}

/**
 * @brief [a部分] SM3优化压缩函数。
 * 优化实现采用以下策略：
 * 1. 消息扩展采用查表法以减少重复计算
 * 2. 使用循环展开减少循环开销
 * 3. 采用更直接的计算方式减少中间变量
 */
void SM3::compress_optimized(const uint8_t block[SM3_BLOCK_SIZE]) {
    uint32_t W[68], W_prime[64];
    uint32_t A, B, C, D, E, F, G, H;
    uint32_t T_j, SS1, SS2, TT1, TT2;

    // 1. 消息扩展 - 处理前16个字
    for (int j = 0; j < 16; j++) {
        GET_UINT32_BE(W[j], block, j * 4);
    }

    // 批量计算消息扩展值
    for (int j = 16; j < 68; j++) {
        W[j] = P1(W[j - 16] ^ W[j - 9] ^ ROTL(W[j - 3], 15)) ^ ROTL(W[j - 13], 7) ^ W[j - 6];
    }

    // 预计算W'值
    for (int j = 0; j < 64; j++) {
        W_prime[j] = W[j] ^ W[j + 4];
    }

    // 2. 初始化工作变量
    A = state[0]; B = state[1]; C = state[2]; D = state[3];
    E = state[4]; F = state[5]; G = state[6]; H = state[7];

    // 3. 压缩函数主循环 - 分为前16轮和后48轮
    // 前16轮
    for (int j = 0; j < 16; j++) {
        T_j = ROTL(T_00_15, j);
        SS1 = ROTL(ROTL(A, 12) + E + T_j, 7);
        SS2 = SS1 ^ ROTL(A, 12);
        
        TT1 = FF_00_15(A, B, C) + D + SS2 + W_prime[j];
        TT2 = GG_00_15(E, F, G) + H + SS1 + W[j];

        D = C;
        C = ROTL(B, 9);
        B = A;
        A = TT1;
        H = G;
        G = ROTL(F, 19);
        F = E;
        E = P0(TT2);
    }

    // 后48轮 - 使用4轮为一组的循环展开
    for (int j = 16; j < 64; j += 4) {
        // 第一轮
        T_j = ROTL(T_16_63, j);
        SS1 = ROTL(ROTL(A, 12) + E + T_j, 7);
        SS2 = SS1 ^ ROTL(A, 12);
        TT1 = FF_16_63(A, B, C) + D + SS2 + W_prime[j];
        TT2 = GG_16_63(E, F, G) + H + SS1 + W[j];
        D = C;
        C = ROTL(B, 9);
        B = A;
        A = TT1;
        H = G;
        G = ROTL(F, 19);
        F = E;
        E = P0(TT2);

        // 第二轮
        T_j = ROTL(T_16_63, j+1);
        SS1 = ROTL(ROTL(A, 12) + E + T_j, 7);
        SS2 = SS1 ^ ROTL(A, 12);
        TT1 = FF_16_63(A, B, C) + D + SS2 + W_prime[j+1];
        TT2 = GG_16_63(E, F, G) + H + SS1 + W[j+1];
        D = C;
        C = ROTL(B, 9);
        B = A;
        A = TT1;
        H = G;
        G = ROTL(F, 19);
        F = E;
        E = P0(TT2);

        // 第三轮
        T_j = ROTL(T_16_63, j+2);
        SS1 = ROTL(ROTL(A, 12) + E + T_j, 7);
        SS2 = SS1 ^ ROTL(A, 12);
        TT1 = FF_16_63(A, B, C) + D + SS2 + W_prime[j+2];
        TT2 = GG_16_63(E, F, G) + H + SS1 + W[j+2];
        D = C;
        C = ROTL(B, 9);
        B = A;
        A = TT1;
        H = G;
        G = ROTL(F, 19);
        F = E;
        E = P0(TT2);

        // 第四轮
        T_j = ROTL(T_16_63, j+3);
        SS1 = ROTL(ROTL(A, 12) + E + T_j, 7);
        SS2 = SS1 ^ ROTL(A, 12);
        TT1 = FF_16_63(A, B, C) + D + SS2 + W_prime[j+3];
        TT2 = GG_16_63(E, F, G) + H + SS1 + W[j+3];
        D = C;
        C = ROTL(B, 9);
        B = A;
        A = TT1;
        H = G;
        G = ROTL(F, 19);
        F = E;
        E = P0(TT2);
    }

    // 4. 更新状态
    state[0] ^= A; state[1] ^= B; state[2] ^= C; state[3] ^= D;
    state[4] ^= E; state[5] ^= F; state[6] ^= G; state[7] ^= H;
}

// [b部分] 长度扩展攻击实现
std::vector<uint8_t> SM3::length_extension_attack(
    const std::vector<uint8_t>& original_hash,
    uint64_t original_len,
    const std::vector<uint8_t>& extra_data) 
{
    if (original_hash.size() != SM3_DIGEST_LENGTH) {
        throw std::invalid_argument("Original hash must be 32 bytes.");
    }

    SM3 attacker_sm3;
    uint32_t internal_state[8];
    for(int i = 0; i < 8; ++i) {
        GET_UINT32_BE(internal_state[i], original_hash.data(), i * 4);
    }

    // 1. 用已知的哈希值作为内部状态来初始化 
    // 2. 伪造消息总长度。长度是原始消息长度加上其填充的长度
    uint64_t padded_original_len = ((original_len + 8) / SM3_BLOCK_SIZE + 1) * SM3_BLOCK_SIZE;
    attacker_sm3.init_with_state(internal_state, padded_original_len);

    // 3. 用新数据更新
    attacker_sm3.update(extra_data);
    
    // 4. 计算出最终的伪造哈希
    return attacker_sm3.final();
}

void SM3::init_with_state(const uint32_t known_state[8], uint64_t known_len) {
    memcpy(state, known_state, sizeof(state));
    total_len = known_len; // 设置伪造的已处理消息长度
    buflen = 0;
    memset(buffer, 0, SM3_BLOCK_SIZE);
}
