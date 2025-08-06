#ifndef SM3_HPP
#define SM3_HPP

#include <vector>
#include <string>
#include <cstdint>
#include <cstddef>

// SM3摘要长度（字节）
constexpr size_t SM3_DIGEST_LENGTH = 32;
// SM3消息分组长度（字节）
constexpr size_t SM3_BLOCK_SIZE = 64;

class SM3 {
public:
    /**
     * @brief 构造函数。
     * @param use_optimized 是否使用优化版本的压缩函数。
     */
    SM3(bool use_optimized = true);

    /**
     * @brief 初始化哈希上下文，重置状态。
     */
    void init();

    /**
     * @brief 更新哈希值。
     * @param data 指向输入数据的指针。
     * @param len 输入数据的长度。
     */
    void update(const uint8_t* data, size_t len);

    /**
     * @brief 更新哈希值（使用std::vector<uint8_t>）。
     * @param data 输入数据。
     */
    void update(const std::vector<uint8_t>& data);

    /**
     * @brief 最终确定哈希值并输出结果。
     * @param digest 用于存放32字节哈希结果的缓冲区。
     */
    void final(uint8_t digest[SM3_DIGEST_LENGTH]);
    
    /**
     * @brief 最终确定哈希值并返回结果。
     * @return 包含32字节哈希结果的vector。
     */
    std::vector<uint8_t> final();

    /**
     * @brief 一次性计算哈希值的静态工具函数。
     * @param data 输入数据。
     * @param digest 用于存放32字节哈希结果的缓冲区。
     * @param use_optimized 是否使用优化版本。
     */
    static void hash(const std::vector<uint8_t>& data, uint8_t digest[SM3_DIGEST_LENGTH], bool use_optimized = true);

    /**
     * @brief 一次性计算哈希值的静态工具函数，返回vector。
     * @param data 输入数据。
     * @param use_optimized 是否使用优化版本。
     * @return 包含32字节哈希结果的vector。
     */
    static std::vector<uint8_t> hash(const std::vector<uint8_t>& data, bool use_optimized = true);

    /**
     * @brief [b部分] 验证长度扩展攻击。
     * @param original_hash 原始消息的已知哈希值。
     * @param original_len 原始消息的长度（字节）。
     * @param extra_data 要附加的数据。
     * @return 伪造的完整消息的哈希值。
     */
    static std::vector<uint8_t> length_extension_attack(
        const std::vector<uint8_t>& original_hash,
        uint64_t original_len,
        const std::vector<uint8_t>& extra_data);

private:
    uint32_t state[8];
    uint64_t total_len;
    uint8_t buffer[SM3_BLOCK_SIZE];
    size_t buflen;
    bool use_optimized_compress; // 标记使用哪个压缩函数

    // 用于长度扩展攻击的特殊初始化
    void init_with_state(const uint32_t known_state[8], uint64_t known_len);

    // 基础压缩函数
    void compress_basic(const uint8_t block[SM3_BLOCK_SIZE]);
    // 优化压缩函数
    void compress_optimized(const uint8_t block[SM3_BLOCK_SIZE]);
};

#endif // SM3_HPP
