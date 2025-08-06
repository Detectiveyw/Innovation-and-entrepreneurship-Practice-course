#include "merkle_tree.hpp"
#include <stdexcept>
#include <cstring>

// [c部分] 构造函数：构建默克尔树
MerkleTree::MerkleTree(const std::vector<std::vector<uint8_t>>& leaves_data) {
    if (leaves_data.empty()) {
        throw std::invalid_argument("Cannot build Merkle tree from empty leaves.");
    }

    // 1. 创建叶子节点层
    std::vector<std::unique_ptr<MerkleNode>> current_level;
    leaf_nodes.reserve(leaves_data.size());
    for (const auto& data : leaves_data) {
        auto node = std::make_unique<MerkleNode>();
        node->hash = hash_leaf(data);
        leaf_nodes.push_back(node.get());
        current_level.push_back(std::move(node));
    }

    // 2. 自底向上构建树
    while (current_level.size() > 1) {
        // 如果当前层节点数为奇数，则复制最后一个节点 
        if (current_level.size() % 2 != 0) {
            auto last_node = std::make_unique<MerkleNode>();
            last_node->hash = current_level.back()->hash;
            // 虽然复制了哈希，但它不是原始叶子节点之一
            current_level.push_back(std::move(last_node));
        }

        std::vector<std::unique_ptr<MerkleNode>> next_level;
        for (size_t i = 0; i < current_level.size(); i += 2) {
            auto parent_node = std::make_unique<MerkleNode>();
            parent_node->hash = hash_internal_node(current_level[i]->hash, current_level[i+1]->hash);
            
            parent_node->left = std::move(current_level[i]);
            parent_node->right = std::move(current_level[i+1]);
            parent_node->left->parent = parent_node.get();
            parent_node->right->parent = parent_node.get();

            next_level.push_back(std::move(parent_node));
        }
        current_level = std::move(next_level);
    }
    root = std::move(current_level[0]);
}

const std::vector<uint8_t>& MerkleTree::get_root_hash() const {
    if (!root) {
        static std::vector<uint8_t> empty_hash;
        return empty_hash;
    }
    return root->hash;
}

// [c部分] 获取存在性证明
MerkleProof MerkleTree::get_inclusion_proof(size_t leaf_index) {
    if (leaf_index >= leaf_nodes.size()) {
        throw std::out_of_range("Leaf index out of range.");
    }
    
    MerkleProof proof;
    MerkleNode* current = leaf_nodes[leaf_index];

    while(current->parent != nullptr) {
        MerkleNode* parent = current->parent;
        MerkleProofNode proof_node;
        if (parent->left.get() == current) { // 当前节点是左孩子
            proof_node.hash = parent->right->hash;
            proof_node.position = 1; // 兄弟在右边
        } else { // 当前节点是右孩子
            proof_node.hash = parent->left->hash;
            proof_node.position = 0; // 兄弟在左边
        }
        proof.path.push_back(proof_node);
        current = parent;
    }
    return proof;
}

// [c部分] 获取不存在性证明
MerkleProof MerkleTree::get_exclusion_proof(size_t index) {
    // 不存在性证明通过提供该位置上实际存在元素的“存在性证明”来完成
    return get_inclusion_proof(index);
}


// [c部分] 验证存在性证明
bool MerkleTree::verify_inclusion_proof(
    const std::vector<uint8_t>& root_hash,
    const std::vector<uint8_t>& leaf_data,
    const MerkleProof& proof)
{
    std::vector<uint8_t> current_hash = hash_leaf(leaf_data);

    for (const auto& proof_node : proof.path) {
        if (proof_node.position == 1) { // 兄弟在右边
            current_hash = hash_internal_node(current_hash, proof_node.hash);
        } else { // 兄弟在左边
            current_hash = hash_internal_node(proof_node.hash, current_hash);
        }
    }
    return current_hash == root_hash;
}

// [c部分] 验证不存在性证明
bool MerkleTree::verify_exclusion_proof(
    const std::vector<uint8_t>& root_hash,
    const std::vector<uint8_t>& non_existent_data,
    const std::vector<uint8_t>& actual_data_at_index,
    const MerkleProof& proof)
{
    // 1. 确认声称不存在的数据与实际数据确实不同
    if (non_existent_data == actual_data_at_index) {
        return false; // 数据实际上存在
    }

    // 2. 验证实际数据的存在性证明。如果证明有效，则说明该位置已被
    //    `actual_data_at_index`占据，从而证明`non_existent_data`不存在于此。
    return verify_inclusion_proof(root_hash, actual_data_at_index, proof);
}


// [c部分] RFC6962 叶子哈希: H(0x00 || leaf_data) 
std::vector<uint8_t> MerkleTree::hash_leaf(const std::vector<uint8_t>& data) {
    std::vector<uint8_t> input;
    input.reserve(1 + data.size());
    input.push_back(0x00);
    input.insert(input.end(), data.begin(), data.end());
    return SM3::hash(input);
}

// [c部分] RFC6962 内部节点哈希: H(0x01 || left_hash || right_hash) 
std::vector<uint8_t> MerkleTree::hash_internal_node(const std::vector<uint8_t>& left, const std::vector<uint8_t>& right) {
    std::vector<uint8_t> input;
    input.reserve(1 + left.size() + right.size());
    input.push_back(0x01);
    input.insert(input.end(), left.begin(), left.end());
    input.insert(input.end(), right.begin(), right.end());
    return SM3::hash(input);
}
