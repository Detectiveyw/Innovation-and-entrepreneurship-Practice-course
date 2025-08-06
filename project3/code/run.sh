#!/bin/bash

# 脚本将在遇到任何错误时退出
set -e

# --- 1. 清理和准备 ---
echo "--- Cleaning up old files ---"
rm -f poseidon2.r1cs poseidon2.sym poseidon2_js/* witness.wtns proof.json public.json input.json *.zkey verification_key.json

# --- 2. 编译电路 ---
echo "--- Compiling circuit (poseidon2.circom) ---"
# 这会生成 poseidon2.r1cs (约束系统) 和 poseidon2_js 目录 (包含WASM和JS代码)
circom poseidon2.circom --r1cs --wasm --sym

# --- 3. 查看电路信息 ---
echo "--- Circuit Info ---"
snarkjs r1cs info poseidon2.r1cs

# --- 4. 可信设置 (Groth16) ---
# 这部分需要一个 Powers of Tau 文件。如果本地没有，snarkjs会尝试下载。
# 对于真实应用，需要一个安全的多方计算仪式。这里我们使用一个现成的文件。
echo "--- Performing trusted setup (Groth16) ---"
if [ ! -f pot14_final.ptau ]; then
    echo "Downloading Powers of Tau file..."
    wget https://hermez.s3-eu-west-1.amazonaws.com/powersOfTau28_hez_final_14.ptau -O pot14_final.ptau
fi

# 4.1 Phase 1: 生成初始 .zkey 文件
snarkjs groth16 setup poseidon2.r1cs pot14_final.ptau poseidon2_0000.zkey
echo "Generated poseidon2_0000.zkey"

# 4.2 Phase 2: 贡献 (这里我们只做一个虚拟贡献)
snarkjs zkey contribute poseidon2_0000.zkey poseidon2_final.zkey --name="Test Contribution" -v
echo "Generated poseidon2_final.zkey"

# 4.3 导出验证密钥
snarkjs zkey export verificationkey poseidon2_final.zkey verification_key.json
echo "Exported verification_key.json"

# --- 5. 生成见证 (Witness) ---
echo "--- Generating witness ---"
# 5.1 首先，用JS脚本生成 input.json
node generate_witness.js

# 5.2 然后，使用WASM计算器生成 witness.wtns
# 进入JS目录执行
cd poseidon2_js
node generate_witness.js poseidon2.wasm ../input.json ../witness.wtns
cd ..
echo "Generated witness.wtns"

# --- 6. 生成证明 ---
echo "--- Generating proof ---"
snarkjs groth16 prove poseidon2_final.zkey witness.wtns proof.json public.json
echo "Generated proof.json and public.json"

# --- 7. 验证证明 ---
echo "--- Verifying proof ---"
snarkjs groth16 verify verification_key.json public.json proof.json

echo "--- Verification successful! ---"
