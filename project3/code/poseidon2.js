const { Scalar } = require("ffjavascript");

// Poseidon2 参数 (t=3, d=5, R_F=8, R_P=22 for BN254)
// 从 Neptune 库中获取: https://github.com/filecoin-project/neptune/blob/master/src/parameters/neptune_params.rs
const {
    BN254_POSEIDON2_C,
    BN254_POSEIDON2_M_E,
} = require('./poseidon2_constants.js');

const t = 3;
const R_F = 8;
const R_P = 22;
const d = 5;
const p = Scalar.fromString("21888242871839275222246405745257275088548364400416034343698204186575808495617");

// 正确处理十六进制字符串的辅助函数
function toBigInt(value) {
    if (typeof value === 'string') {
        // 处理没有0x前缀的十六进制字符串
        if (value.match(/^[0-9a-fA-F]+$/) && !value.startsWith('0x')) {
            return Scalar.fromString('0x' + value);
        }
        return Scalar.fromString(value);
    }
    return Scalar.e(value);
}

// 将常量和矩阵转换为 Scalar
const C = BN254_POSEIDON2_C.map(row => row.map(c => toBigInt(c)));
const M_E = BN254_POSEIDON2_M_E.map(row => row.map(m => toBigInt(m)));

// S-Box函数 - 计算x^d mod p
function sbox(x) {
    // 正确用法：Scalar.mod(Scalar.pow(x, d), p)
    // 而不是 Scalar.pow(x, d).mod(p)
    return Scalar.mod(Scalar.pow(x, d), p);
}

function externalMatrixMul(state) {
    const newState = new Array(t).fill(Scalar.e(0));
    for (let i = 0; i < t; i++) {
        for (let j = 0; j < t; j++) {
            // 正确用法：累加 Scalar.add(current, newValue)
            newState[i] = Scalar.add(newState[i], Scalar.mul(M_E[i][j], state[j]));
        }
        // 取模操作
        newState[i] = Scalar.mod(newState[i], p);
    }
    return newState;
}

function internalMatrixMul(state) {
    let sum = Scalar.e(0);
    for (let i = 0; i < t; i++) {
        sum = Scalar.add(sum, state[i]);
    }
    sum = Scalar.mod(sum, p);
    
    return state.map(x => Scalar.mod(Scalar.add(x, sum), p));
}

function poseidon2(inputs) {
    if (inputs.length !== t - 1) {
        throw new Error(`Expected ${t - 1} inputs, got ${inputs.length}`);
    }

    // 状态初始化
    let state = [Scalar.e(0)];
    for (let i = 0; i < inputs.length; i++) {
        state.push(Scalar.fromString(inputs[i]));
    }
    let round = 0;

    // 初始外部轮
    for (let i = 0; i < R_F / 2; i++) {
        // AddRoundConstants
        state = state.map((a, j) => Scalar.mod(Scalar.add(a, C[round][j]), p));
        // S-Box
        state = state.map(a => sbox(a));
        // Matrix
        state = externalMatrixMul(state);
        round++;
    }

    // 内部轮
    for (let i = 0; i < R_P; i++) {
        // AddRoundConstants
        state = state.map((a, j) => Scalar.mod(Scalar.add(a, C[round][j]), p));
        // S-Box (on first element)
        state[0] = sbox(state[0]);
        // Matrix
        state = internalMatrixMul(state);
        round++;
    }

    // 最终外部轮
    for (let i = 0; i < R_F / 2; i++) {
        // AddRoundConstants
        state = state.map((a, j) => Scalar.mod(Scalar.add(a, C[round][j]), p));
        // S-Box
        state = state.map(a => sbox(a));
        // Matrix
        state = externalMatrixMul(state);
        round++;
    }

    return state[0];
}

// 导出函数
module.exports = {
    poseidon2,
    BN254_POSEIDON2_C,
    BN254_POSEIDON2_M_E,
    t,
    R_F,
    R_P
};
