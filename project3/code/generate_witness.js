const fs = require('fs');
const {
    poseidon2,
    BN254_POSEIDON2_C,
    BN254_POSEIDON2_M_E
} = require('./poseidon2.js');

// 定义电路的输入
// 这是隐私输入，即哈希原象
const preImage = [
    "12345",
    "67890"
];

// 使用链下代码计算对应的哈希值
const calculatedHash = poseidon2(preImage);

// 准备要写入 input.json 的完整输入对象
const circuitInputs = {
    // 隐私输入
    "preImage": preImage,
    // 公开输入
    "hash": calculatedHash.toString(),

    // --- 只包含电路中实际定义的输入信号 ---
    "round_constants": BN254_POSEIDON2_C.map(row => row.map(c => BigInt(c).toString())),
    "M_E": BN254_POSEIDON2_M_E.map(row => row.map(m => BigInt(m).toString()))
};

// 将输入写入 input.json 文件
fs.writeFileSync(
    'input.json',
    JSON.stringify(circuitInputs, null, 2),
    'utf-8'
);

console.log('Witness input file (input.json) generated successfully.');
console.log(`Pre-image: [${preImage[0]}, ${preImage[1]}]`);
console.log(`Hash: ${calculatedHash.toString()}`);
