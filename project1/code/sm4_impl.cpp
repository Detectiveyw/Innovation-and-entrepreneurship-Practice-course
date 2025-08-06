#include "sm4_shared.h"

// 循环左移宏
#define ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

// --- 密钥扩展相关函数 ---

// 密钥扩展中的非线性变换 τ
uint32_t tau_key(uint32_t A) {
    uint8_t b[4];
    from_uint32(A, b);
    b[0] = SM4_SBOX[b[0]];
    b[1] = SM4_SBOX[b[1]];
    b[2] = SM4_SBOX[b[2]];
    b[3] = SM4_SBOX[b[3]];
    return to_uint32(b);
}

// 密钥扩展中的线性变换 L' 
uint32_t L_prime(uint32_t B) {
    return B ^ ROTL(B, 13) ^ ROTL(B, 23);
}

// SM4 密钥扩展函数 
void sm4_set_key(const uint8_t* key, uint32_t* rk) {
    uint32_t K[4];
    K[0] = to_uint32(key);
    K[1] = to_uint32(key + 4);
    K[2] = to_uint32(key + 8);
    K[3] = to_uint32(key + 12);

    K[0] ^= FK[0];
    K[1] ^= FK[1];
    K[2] ^= FK[2];
    K[3] ^= FK[3];

    for (int i = 0; i < SM4_NUM_ROUNDS; ++i) {
        rk[i] = K[0] ^ L_prime(tau_key(K[1] ^ K[2] ^ K[3] ^ CK[i]));
        // 更新K数组作为滑动窗口
        K[0] = K[1];
        K[1] = K[2];
        K[2] = K[3];
        K[3] = rk[i];
    }
}


// --- 基础实现 ---

// 加密/解密中的线性变换 L 
uint32_t L(uint32_t B) {
    return B ^ ROTL(B, 2) ^ ROTL(B, 10) ^ ROTL(B, 18) ^ ROTL(B, 24);
}

// 加密/解密中的非线性变换 τ
uint32_t tau(uint32_t A) {
    uint8_t b[4];
    from_uint32(A, b);
    b[0] = SM4_SBOX[b[0]];
    b[1] = SM4_SBOX[b[1]];
    b[2] = SM4_SBOX[b[2]];
    b[3] = SM4_SBOX[b[3]];
    return to_uint32(b);
}

// 复合变换 T 
uint32_t T(uint32_t V) {
    return L(tau(V));
}

// SM4 基础加密函数 
void sm4_encrypt_basic(const uint8_t* in, uint8_t* out, const uint32_t* rk) {
    uint32_t X[4];
    X[0] = to_uint32(in);
    X[1] = to_uint32(in + 4);
    X[2] = to_uint32(in + 8);
    X[3] = to_uint32(in + 12);

    for (int i = 0; i < SM4_NUM_ROUNDS; ++i) {
        uint32_t temp = X[1] ^ X[2] ^ X[3] ^ rk[i];
        uint32_t X_new = X[0] ^ T(temp);
        X[0] = X[1];
        X[1] = X[2];
        X[2] = X[3];
        X[3] = X_new;
    }

    // 反序变换
    from_uint32(X[3], out);
    from_uint32(X[2], out + 4);
    from_uint32(X[1], out + 8);
    from_uint32(X[0], out + 12);
}

// SM4 基础解密函数
void sm4_decrypt_basic(const uint8_t* in, uint8_t* out, const uint32_t* rk) {
    uint32_t X[4];
    X[0] = to_uint32(in);
    X[1] = to_uint32(in + 4);
    X[2] = to_uint32(in + 8);
    X[3] = to_uint32(in + 12);

    // 解密使用反序的轮密钥
    for (int i = 0; i < SM4_NUM_ROUNDS; ++i) {
        uint32_t temp = X[1] ^ X[2] ^ X[3] ^ rk[31 - i];
        uint32_t X_new = X[0] ^ T(temp);
        X[0] = X[1];
        X[1] = X[2];
        X[2] = X[3];
        X[3] = X_new;
    }

    // 反序变换
    from_uint32(X[3], out);
    from_uint32(X[2], out + 4);
    from_uint32(X[1], out + 8);
    from_uint32(X[0], out + 12);
}

// --- T-Table 优化实现 ---

static uint32_t T_TABLE[4][256];
static bool t_tables_generated = false;

void generate_ttables() {
    if (t_tables_generated) return;
    for (int i = 0; i < 256; ++i) {
        uint32_t s_val = SM4_SBOX[i];
        T_TABLE[0][i] = L(s_val << 24);
        T_TABLE[1][i] = L(s_val << 16);
        T_TABLE[2][i] = L(s_val << 8);
        T_TABLE[3][i] = L(s_val);
    }
    t_tables_generated = true;
}

// 使用T-Table的复合变换 
uint32_t T_ttable(uint32_t V) {
    return T_TABLE[0][(V >> 24) & 0xFF] ^
        T_TABLE[1][(V >> 16) & 0xFF] ^
        T_TABLE[2][(V >> 8) & 0xFF] ^
        T_TABLE[3][(V) & 0xFF];
}

// SM4 T-Table 加密函数 
void sm4_encrypt_ttable(const uint8_t* in, uint8_t* out, const uint32_t* rk) {
    if (!t_tables_generated) generate_ttables();

    uint32_t X[4];
    X[0] = to_uint32(in);
    X[1] = to_uint32(in + 4);
    X[2] = to_uint32(in + 8);
    X[3] = to_uint32(in + 12);

    for (int i = 0; i < 32; i++) {
        uint32_t temp = X[1] ^ X[2] ^ X[3] ^ rk[i];
        uint32_t X_new = X[0] ^ T_ttable(temp);
        X[0] = X[1];
        X[1] = X[2];
        X[2] = X[3];
        X[3] = X_new;
    }

    from_uint32(X[3], out);
    from_uint32(X[2], out + 4);
    from_uint32(X[1], out + 8);
    from_uint32(X[0], out + 12);
}

// SM4 T-Table 解密函数
void sm4_decrypt_ttable(const uint8_t* in, uint8_t* out, const uint32_t* rk) {
    if (!t_tables_generated) generate_ttables();

    uint32_t X[4];
    X[0] = to_uint32(in);
    X[1] = to_uint32(in + 4);
    X[2] = to_uint32(in + 8);
    X[3] = to_uint32(in + 12);

    for (int i = 0; i < 32; i++) {
        uint32_t temp = X[1] ^ X[2] ^ X[3] ^ rk[31 - i];
        uint32_t X_new = X[0] ^ T_ttable(temp);
        X[0] = X[1];
        X[1] = X[2];
        X[2] = X[3];
        X[3] = X_new;
    }

    from_uint32(X[3], out);
    from_uint32(X[2], out + 4);
    from_uint32(X[1], out + 8);
    from_uint32(X[0], out + 12);
}