#include "sm4_shared.h"
#include <chrono>
#include <vector>
#include <memory.h> 

#include "sm4_gcm.h"
#include <iostream>
#include <iomanip>

// 性能和正确性测试函数
void benchmark_and_verify() {
    // 测试数据来自 GB/T 32907-2016 标准附录A
    const uint8_t key[16] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10 };
    const uint8_t plaintext[16] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10 };
    const uint8_t expected_ciphertext[16] = { 0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e, 0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46 };

    uint32_t round_keys[SM4_NUM_ROUNDS];
    uint8_t basic_ct[SM4_BLOCK_SIZE], basic_pt[SM4_BLOCK_SIZE];
    uint8_t ttable_ct[SM4_BLOCK_SIZE], ttable_pt[SM4_BLOCK_SIZE];

    // 生成轮密钥
    sm4_set_key(key, round_keys);

    // --- 正确性验证 ---
    std::cout << "--- Correctness Verification ---" << std::endl;
    std::cout << "Plaintext:                "; print_hex(plaintext, 16);
    std::cout << "Expected Ciphertext:      "; print_hex(expected_ciphertext, 16);

    // 基础版加解密
    sm4_encrypt_basic(plaintext, basic_ct, round_keys);
    std::cout << "Basic Encrypted:          "; print_hex(basic_ct, 16);
    sm4_decrypt_basic(basic_ct, basic_pt, round_keys);
    std::cout << "Basic Decrypted:          "; print_hex(basic_pt, 16);

    // T-Table版加解密
    sm4_encrypt_ttable(plaintext, ttable_ct, round_keys);
    std::cout << "T-Table Encrypted:        "; print_hex(ttable_ct, 16);
    sm4_decrypt_ttable(ttable_ct, ttable_pt, round_keys);
    std::cout << "T-Table Decrypted:        "; print_hex(ttable_pt, 16);

    // 比较结果
    bool ok = true;
    if (memcmp(basic_ct, expected_ciphertext, 16) != 0) {
        std::cout << "[FAIL] Basic encryption output does not match expected value." << std::endl;
        ok = false;
    }
    if (memcmp(ttable_ct, expected_ciphertext, 16) != 0) {
        std::cout << "[FAIL] T-Table encryption output does not match expected value." << std::endl;
        ok = false;
    }
    if (memcmp(basic_pt, plaintext, 16) != 0) {
        std::cout << "[FAIL] Basic decryption failed." << std::endl;
        ok = false;
    }
    if (memcmp(ttable_pt, plaintext, 16) != 0) {
        std::cout << "[FAIL] T-Table decryption failed." << std::endl;
        ok = false;
    }
    if (ok) {
        std::cout << "[PASS] All correctness checks passed!" << std::endl;
    }
    std::cout << std::endl;


    // --- 性能测试 ---
    std::cout << "--- Performance Benchmark ---" << std::endl;
    const int num_iterations = 2000000; // 增加迭代次数以获得更稳定的结果
    uint8_t temp_buffer[SM4_BLOCK_SIZE]; // 避免编译器优化掉循环

    // 测试基础版
    auto start_basic = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < num_iterations; ++i) {
        sm4_encrypt_basic(plaintext, temp_buffer, round_keys);
    }
    auto end_basic = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double, std::milli> duration_basic = end_basic - start_basic;
    double gb_per_sec_basic = (double)num_iterations * SM4_BLOCK_SIZE / (duration_basic.count() / 1000.0) / (1024 * 1024 * 1024);
    std::cout << "Basic Implementation (" << num_iterations << " blocks): "
        << duration_basic.count() << " ms (" << gb_per_sec_basic << " GB/s)" << std::endl;

    // 测试T-Table版
    auto start_ttable = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < num_iterations; ++i) {
        sm4_encrypt_ttable(plaintext, temp_buffer, round_keys);
    }
    auto end_ttable = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double, std::milli> duration_ttable = end_ttable - start_ttable;
    double gb_per_sec_ttable = (double)num_iterations * SM4_BLOCK_SIZE / (duration_ttable.count() / 1000.0) / (1024 * 1024 * 1024);
    std::cout << "T-Table Optimized (" << num_iterations << " blocks):  "
        << duration_ttable.count() << " ms (" << gb_per_sec_ttable << " GB/s)" << std::endl;

    double improvement = (duration_basic.count() - duration_ttable.count()) / duration_basic.count() * 100.0;
    std::cout << "\nOptimization Effect (T-Table vs Basic):" << std::endl;
    std::cout << "  - Speedup: " << std::fixed << std::setprecision(2) << duration_basic.count() / duration_ttable.count() << "x" << std::endl;
    std::cout << "  - Time Reduction: " << std::fixed << std::setprecision(2) << improvement << "%" << std::endl;
}

// 辅助函数：打印十六进制数据
void print_hex_data(const char* label, const uint8_t* data, size_t len) {
    std::cout << label << ": ";
    for (size_t i = 0; i < len; i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
    }
    std::cout << std::dec << std::endl;
}

// 辅助函数：从十六进制字符串转换到字节数组
std::vector<uint8_t> hex_to_bytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        uint8_t byte = (uint8_t)strtol(byteString.c_str(), NULL, 16);
        bytes.push_back(byte);
    }
    return bytes;
}

// SM4-GCM模式的正确性测试
void test_sm4_gcm_correctness() {
    std::cout << "\n--- SM4-GCM 正确性测试 ---" << std::endl;

    // 测试向量
    const uint8_t key[16] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10 };
    const uint8_t iv[12] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b };
    const uint8_t aad[16] = { 0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef };
    const uint8_t plaintext[32] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };

    // 加密和解密缓冲区
    uint8_t ciphertext[32];
    uint8_t tag[SM4_GCM_TAG_SIZE];
    uint8_t decrypted[32];

    // 初始化GCM模式
    sm4_gcm_init(key);

    // 加密
    bool enc_success = sm4_gcm_encrypt(
        key, iv, 12, aad, 16,
        plaintext, 32, ciphertext, tag
    );

    std::cout << "加密结果: " << (enc_success ? "成功" : "失败") << std::endl;
    print_hex_data("明文", plaintext, 32);
    print_hex_data("密文", ciphertext, 32);
    print_hex_data("认证标签", tag, SM4_GCM_TAG_SIZE);

    // 解密并验证
    bool dec_success = sm4_gcm_decrypt(
        key, iv, 12, aad, 16,
        ciphertext, 32, decrypted, tag
    );

    std::cout << "解密结果: " << (dec_success ? "成功" : "失败") << std::endl;
    print_hex_data("解密后的数据", decrypted, 32);

    // 验证解密结果是否与原始明文匹配
    bool match = (memcmp(plaintext, decrypted, 32) == 0);
    std::cout << "解密数据与原始明文" << (match ? "匹配" : "不匹配") << std::endl;

    // 尝试使用无效标签，确保验证失败
    tag[0] ^= 1; // 翻转标签中的一个位
    bool dec_fail = sm4_gcm_decrypt(
        key, iv, 12, aad, 16,
        ciphertext, 32, decrypted, tag
    );
    std::cout << "使用无效标签解密: " << (!dec_fail ? "正确拒绝" : "错误接受") << std::endl;
}

// SM4-GCM性能基准测试
void benchmark_sm4_gcm() {
    std::cout << "\n--- SM4-GCM 性能基准测试 ---" << std::endl;

    // 测试参数
    const int iterations = 100000;  // 重复次数
    const int data_sizes[] = { 16, 64, 256, 1024, 4096 };  // 数据大小（字节）

    // 测试数据
    uint8_t key[16] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10 };
    uint8_t iv[12] = { 0 }; // 12字节IV
    uint8_t aad[16] = { 0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef };
    uint8_t tag[SM4_GCM_TAG_SIZE];

    // 初始化GCM
    sm4_gcm_init(key);

    std::cout << "数据大小 | 加密速度 | 解密速度 | 综合速度" << std::endl;
    std::cout << "---------|----------|----------|----------" << std::endl;

    for (int size : data_sizes) {
        // 创建缓冲区
        std::vector<uint8_t> plaintext(size, 0xaa);
        std::vector<uint8_t> ciphertext(size);
        std::vector<uint8_t> decrypted(size);

        // 基准测试加密
        auto start_encrypt = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < iterations; i++) {
            sm4_gcm_encrypt(
                key, iv, 12, aad, 16,
                plaintext.data(), size,
                ciphertext.data(), tag
            );
        }
        auto end_encrypt = std::chrono::high_resolution_clock::now();
        auto duration_encrypt = std::chrono::duration_cast<std::chrono::microseconds>(end_encrypt - start_encrypt).count();
        double throughput_encrypt = (double)iterations * size / (duration_encrypt / 1000000.0) / (1024 * 1024); // MB/s

        // 基准测试解密
        auto start_decrypt = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < iterations; i++) {
            sm4_gcm_decrypt(
                key, iv, 12, aad, 16,
                ciphertext.data(), size,
                decrypted.data(), tag
            );
        }
        auto end_decrypt = std::chrono::high_resolution_clock::now();
        auto duration_decrypt = std::chrono::duration_cast<std::chrono::microseconds>(end_decrypt - start_decrypt).count();
        double throughput_decrypt = (double)iterations * size / (duration_decrypt / 1000000.0) / (1024 * 1024); // MB/s

        // 计算综合吞吐量
        double combined = (double)iterations * 2 * size / ((duration_encrypt + duration_decrypt) / 1000000.0) / (1024 * 1024);

        // 打印结果
        std::cout << std::setw(8) << size << "B | "
            << std::fixed << std::setprecision(2) << throughput_encrypt << " MB/s | "
            << std::fixed << std::setprecision(2) << throughput_decrypt << " MB/s | "
            << std::fixed << std::setprecision(2) << combined << " MB/s" << std::endl;
    }

}

int main() {
    benchmark_and_verify();
    test_sm4_gcm_correctness();
    benchmark_sm4_gcm();
    return 0;
}