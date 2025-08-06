#ifndef MERKLE_TREE_HPP
#define MERKLE_TREE_HPP

#include "sm3.hpp"
#include <vector>
#include <memory>
#include <cstdint>

// 定义默克尔树节点和证明的结构
struct MerkleNode {
    std::vector<uint8_t> hash;
    std::unique_ptr<MerkleNode> left = nullptr;
    std::unique_ptr<MerkleNode> right = nullptr;
    MerkleNode* parent = nullptr;
};

// 默克尔证明路径中的一个节点
struct MerkleProofNode {
    std::vector<uint8_t> hash;
    int position; // 0 for left, 1 for right
};

// 完整的默克尔证明
struct MerkleProof {
    std::vector<MerkleProofNode> path;
};


class MerkleTree {
public:
    /**
     * @brief 构造函数，从叶子节点数据构建默克尔树。
     * @param leaves_data 一个包含所有叶子节点数据的vector。
     */
    MerkleTree(const std::vector<std::vector<uint8_t>>& leaves_data);

    /**
     * @brief 获取默克尔树的根哈希。
     * @return 根哈希值。
     */
    const std::vector<uint8_t>& get_root_hash() const;

    /**
     * @brief [c部分] 为指定索引的叶子构建存在性证明（Inclusion Proof）。
     * @param leaf_index 叶子的索引。
     * @return 默克尔证明。
     */
    MerkleProof get_inclusion_proof(size_t leaf_index);

    /**
     * @brief [c部分] 为一个不存在的元素构建不存在性证明（Exclusion Proof）。
     * 在有序叶子集合的场景下，这通过提供该位置上实际存在元素的证明来完成。
     * @param index 要证明其不存在的元素的索引。
     * @return 对应索引上实际存在元素的默克尔证明。
     */
    MerkleProof get_exclusion_proof(size_t index);


    /**
     * @brief [c部分] 验证一个存在性证明。
     * @param root_hash 树的根哈希。
     * @param leaf_data 要验证的叶子数据。
     * @param proof 存在性证明。
     * @return 如果证明有效，返回true。
     */
    static bool verify_inclusion_proof(
        const std::vector<uint8_t>& root_hash,
        const std::vector<uint8_t>& leaf_data,
        const MerkleProof& proof);
    
    /**
     * @brief [c部分] 验证一个不存在性证明。
     * @param root_hash 树的根哈希。
     * @param non_existent_data 声称不存在的数据。
     * @param actual_data_at_index 证明路径对应的实际数据。
     * @param proof 对应索引上实际存在元素的证明。
     * @return 如果证明有效且数据确实不存在，返回true。
     */
    static bool verify_exclusion_proof(
        const std::vector<uint8_t>& root_hash,
        const std::vector<uint8_t>& non_existent_data,
        const std::vector<uint8_t>& actual_data_at_index,
        const MerkleProof& proof);

private:
    std::unique_ptr<MerkleNode> root;
    std::vector<MerkleNode*> leaf_nodes;

    // 根据RFC6962对叶子节点进行哈希
    static std::vector<uint8_t> hash_leaf(const std::vector<uint8_t>& data);
    // 根据RFC6962对内部节点进行哈希
    static std::vector<uint8_t> hash_internal_node(const std::vector<uint8_t>& left, const std::vector<uint8_t>& right);
};

#endif // MERKLE_TREE_HPP
