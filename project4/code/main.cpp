#include <iostream>
#include <vector>
#include <string>
#include <chrono>
#include <iomanip>
#include "sm3.hpp"
#include "merkle_tree.hpp"

// 辅助函数：打印哈希值
void print_hash(const std::string& label, const std::vector<uint8_t>& hash) {
    std::cout << std::left << std::setw(35) << label << ": ";
    std::cout << std::hex << std::setfill('0');
    for (uint8_t byte : hash) {
        std::cout << std::setw(2) << static_cast<int>(byte);
    }
    std::cout << std::dec << std::endl;
}

// 辅助函数：将字符串转为vector<uint8_t>
std::vector<uint8_t> s2v(const std::string& s) {
    return std::vector<uint8_t>(s.begin(), s.end());
}


// ======================= a部分: SM3实现与优化 =======================
void demo_sm3_implementation() {
    std::cout << "--- a部分: SM3实现与优化 ---\n";
    std::string message_str = "abc";
    std::vector<uint8_t> message = s2v(message_str);
    
    std::vector<uint8_t> expected_hash = {
        0x66, 0xc7, 0xf0, 0xf4, 0x62, 0xee, 0xed, 0xd9, 0xd1, 0xf2, 0xd4, 0x6b, 
        0xdc, 0x10, 0xe4, 0xe2, 0x41, 0x67, 0xc4, 0x87, 0x5c, 0xf2, 0xf7, 0xa2, 
        0x29, 0x7d, 0xa0, 0x2b, 0x8f, 0x4b, 0xa8, 0xe0
    };

    std::cout << "输入消息: \"" << message_str << "\"\n";
    print_hash("期望哈希值", expected_hash);

    // 基础实现
    auto basic_hash = SM3::hash(message, false);
    print_hash("基础实现哈希", basic_hash);
    std::cout << "基础实现是否正确: " << (basic_hash == expected_hash ? "是" : "否") << "\n";

    // 优化实现
    auto optimized_hash = SM3::hash(message, true);
    print_hash("优化实现哈希", optimized_hash);
    std::cout << "优化实现是否正确: " << (optimized_hash == expected_hash ? "是" : "否") << "\n\n";
    
    // 效率对比
    std::cout << "开始进行效率测试 (处理100MB数据)...\n";
    size_t data_size = 100 * 1024 * 1024;
    std::vector<uint8_t> large_data(data_size, 'a');
    
    auto start = std::chrono::high_resolution_clock::now();
    SM3::hash(large_data, false);
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double, std::milli> basic_time = end - start;
    double basic_speed = (data_size / (1024.0 * 1024.0)) / (basic_time.count() / 1000.0);
    std::cout << "基础实现耗时: " << basic_time.count() << " ms, 速度: " << basic_speed << " MB/s\n";

    start = std::chrono::high_resolution_clock::now();
    SM3::hash(large_data, true);
    end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double, std::milli> optimized_time = end - start;
    double optimized_speed = (data_size / (1024.0 * 1024.0)) / (optimized_time.count() / 1000.0);
    std::cout << "优化实现耗时: " << optimized_time.count() << " ms, 速度: " << optimized_speed << " MB/s\n";
    std::cout << "优化提升比例: " << (basic_time.count() / optimized_time.count()) << "倍\n";
}

// ======================= b部分: 长度扩展攻击 =======================
void demo_length_extension_attack() {
    std::cout << "\n--- b部分: 长度扩展攻击验证 ---\n";
    
    std::string secret = "my-super-secret-key";
    std::string original_data_str = "user=guest&command=list";
    std::string append_data_str = "&command=grant&user=admin";
    
    auto secret_vec = s2v(secret);
    auto original_data = s2v(original_data_str);
    auto append_data = s2v(append_data_str);
    
    // 1. 合法用户计算原始消息的MAC: H(secret || original_data)
    std::vector<uint8_t> full_message = secret_vec;
    full_message.insert(full_message.end(), original_data.begin(), original_data.end());
    auto original_mac = SM3::hash(full_message);
    print_hash("原始MAC H(secret || data)", original_mac);

    // 2. 攻击者在不知道secret的情况下，伪造MAC
    // 攻击者已知: original_data, original_mac, 并猜测secret的长度
    // [修正] C++的string用 .length() 或 .size() 均可，但vector只能用 .size()
    auto forged_mac = SM3::length_extension_attack(original_mac, secret.length() + original_data.size(), append_data);
    print_hash("伪造的MAC H(secret||pad||append)", forged_mac);

    // 3. 服务端验证 (为了对比，我们在此模拟服务端计算)
    // 服务端收到的消息是: original_data || padding_glue || append_data
    // 对应的哈希计算应该是 H(secret || original_data || padding_glue || append_data)
    // 我们需要手动构造这个被攻击者实际伪造的消息
    // [修正] 此处同样使用 .size()
    uint64_t original_len = secret.length() + original_data.size();
    uint64_t padded_len = ((original_len + 8) / SM3_BLOCK_SIZE + 1) * SM3_BLOCK_SIZE;
    size_t padding_len = padded_len - original_len;

    std::vector<uint8_t> server_side_msg = full_message;
    server_side_msg.push_back(0x80);
    server_side_msg.insert(server_side_msg.end(), padding_len - 1, 0x00);
    
    // 替换最后8个字节为原始长度（比特）
    uint64_t total_bits = original_len * 8;
    for(int i = 0; i < 8; ++i) {
        server_side_msg[server_side_msg.size() - 8 + i] = (uint8_t)(total_bits >> (56 - i * 8));
    }

    server_side_msg.insert(server_side_msg.end(), append_data.begin(), append_data.end());
    
    auto legitimate_extended_mac = SM3::hash(server_side_msg);
    print_hash("合法的扩展MAC", legitimate_extended_mac);

    if (forged_mac == legitimate_extended_mac) {
        std::cout << "成功: 伪造的MAC与合法的扩展MAC匹配。攻击得到验证。\n";
    } else {
        std::cout << "失败: 伪造的MAC不匹配。\n";
    }
}


// ======================= c部分: 默克尔树 =======================
constexpr size_t NUM_LEAVES = 100000;
constexpr size_t LEAF_SIZE = 32;

void demo_merkle_tree() {
    std::cout << "\n--- c部分: Merkle树 (RFC6962, 10万叶子节点) ---\n";

    // 1. 生成10万个叶子节点数据
    std::cout << "正在生成 " << NUM_LEAVES << " 个叶子节点数据...\n";
    std::vector<std::vector<uint8_t>> leaves_data;
    leaves_data.reserve(NUM_LEAVES);
    for (size_t i = 0; i < NUM_LEAVES; ++i) {
        std::string leaf_str = "leaf-data-" + std::to_string(i);
        std::vector<uint8_t> leaf_vec = s2v(leaf_str);
        leaf_vec.resize(LEAF_SIZE, 0); // 统一大小
        leaves_data.push_back(leaf_vec);
    }
    
    // 2. 构建默克尔树
    std::cout << "正在构建默克尔树...\n";
    auto start = std::chrono::high_resolution_clock::now();
    MerkleTree tree(leaves_data);
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double, std::milli> build_time = end - start;
    std::cout << "默克尔树构建完成，耗时: " << build_time.count() << " ms.\n";
    auto root_hash = tree.get_root_hash();
    print_hash("默克尔树根哈希", root_hash);

    // 3. 存在性证明 (Inclusion Proof)
    std::cout << "\n--- 存在性证明演示 ---\n";
    size_t proof_index = 77777;
    std::cout << "正在为第 " << proof_index << " 个叶子生成存在性证明...\n";
    MerkleProof inclusion_proof = tree.get_inclusion_proof(proof_index);
    std::cout << "正在验证证明...\n";
    bool is_valid = MerkleTree::verify_inclusion_proof(root_hash, leaves_data[proof_index], inclusion_proof);
    if (is_valid) {
        std::cout << "成功: 第 " << proof_index << " 个叶子的存在性证明有效。\n";
    } else {
        std::cout << "失败: 第 " << proof_index << " 个叶子的存在性证明无效。\n";
    }
    
    // 4. 不存在性证明 (Exclusion Proof)
    std::cout << "\n--- 不存在性证明演示 ---\n";
    size_t non_existent_index = 88888;
    std::string non_existent_str = "i-do-not-exist";
    std::vector<uint8_t> non_existent_data = s2v(non_existent_str);
    non_existent_data.resize(LEAF_SIZE, 0);
    
    std::cout << "正在证明数据在索引 " << non_existent_index << " 处不存在...\n";
    std::cout << "  (通过证明该索引处的实际数据来间接证明)\n";
    
    MerkleProof exclusion_proof = tree.get_exclusion_proof(non_existent_index);
    std::cout << "正在验证不存在性证明...\n";
    bool is_excluded = MerkleTree::verify_exclusion_proof(root_hash, non_existent_data, leaves_data[non_existent_index], exclusion_proof);
    if (is_excluded) {
        std::cout << "成功: 不存在性证明有效。数据确认不在索引 " << non_existent_index << " 处。\n";
    } else {
        std::cout << "失败: 不存在性证明无效。\n";
    }
}


int main() {
    demo_sm3_implementation();
    demo_length_extension_attack();
    demo_merkle_tree();
    return 0;
}
