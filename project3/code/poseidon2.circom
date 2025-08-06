pragma circom 2.1.5;

/*
 * ==========================================================
 * Helper Templates (Top Level)
 * ==========================================================
 */

// S-Box (x^5)
template Sbox() {
    signal input x;
    signal output out;
    signal x2 <== x * x;
    signal x4 <== x2 * x2;
    out <== x4 * x;
}

// Add Round Constants
template AddRoundConstants(t) {
    signal input state[t];
    signal input C[t];
    signal output out[t];

    for (var i = 0; i < t; i++) {
        out[i] <== state[i] + C[i];
    }
}

// External Matrix Multiplication (M_E)
// This version explicitly breaks down the computation into simple quadratic constraints.
template ExternalMatrix(t) {
    signal input state[t];
    signal input M[t][t];
    signal output out[t];

    // Pre-declare all intermediate signals needed for the calculation.
    signal products[t][t];
    signal acc[t][t + 1];

    for (var i = 0; i < t; i++) {
        // Initialize accumulator for this row
        acc[i][0] <== 0;
        for (var j = 0; j < t; j++) {
            // 1. Create a simple quadratic constraint for each product.
            // This is of the form: products - state * M = 0
            products[i][j] <== state[j] * M[i][j];
            
            // 2. Create a simple linear constraint for each accumulation.
            // This is of the form: acc[j+1] - acc[j] - products = 0
            acc[i][j + 1] <== acc[i][j] + products[i][j];
        }
        // 3. The final assignment is a simple linear constraint.
        // This is of the form: out - acc = 0
        out[i] <== acc[i][t];
    }
}


// Internal Matrix Multiplication (M_I)
template InternalMatrix(t) {
    signal input state[t];
    signal output out[t];

    var sum = 0;
    for (var i = 0; i < t; i++) {
        sum += state[i];
    }

    for (var i = 0; i < t; i++) {
        out[i] <== state[i] + sum;
    }
}


/*
 * ==========================================================
 * Main Poseidon2 Hasher Template
 * ==========================================================
 */
template Poseidon2(t, R_F, R_P) {
    signal input in[t-1];
    signal output out;

    signal input round_constants[R_F + R_P][t];
    signal input M_E[t][t];

    var NUM_ROUNDS = R_F + R_P;

    // --- Pre-declare all components and signals for all rounds ---
    component arc[NUM_ROUNDS];
    component sboxes[R_F * t + R_P]; // Total S-Boxes needed
    component mat_ext[R_F];
    component mat_int[R_P];

    // --- State chaining signals ---
    signal state[NUM_ROUNDS + 1][t];
    signal sbox_outputs[NUM_ROUNDS][t];


    // --- Initial State ---
    state[0][0] <== 0;
    for (var i = 1; i < t; i++) {
        state[0][i] <== in[i-1];
    }

    var r = 0; // round counter
    var sbox_c = 0; // s-box counter
    var mat_ext_c = 0; // external matrix counter
    var mat_int_c = 0; // internal matrix counter

    // --- Initial External Rounds ---
    for (var i = 0; i < R_F / 2; i++) {
        arc[r] = AddRoundConstants(t);
        arc[r].state <== state[r];
        for(var k=0; k<t; k++) arc[r].C[k] <== round_constants[r][k];

        for (var k = 0; k < t; k++) {
            sboxes[sbox_c] = Sbox();
            sboxes[sbox_c].x <== arc[r].out[k];
            sbox_outputs[r][k] <== sboxes[sbox_c].out;
            sbox_c++;
        }

        mat_ext[mat_ext_c] = ExternalMatrix(t);
        mat_ext[mat_ext_c].state <== sbox_outputs[r];
        for(var k=0; k<t; k++) for(var l=0; l<t; l++) mat_ext[mat_ext_c].M[k][l] <== M_E[k][l];
        
        state[r+1] <== mat_ext[mat_ext_c].out;
        mat_ext_c++;
        r++;
    }

    // --- Internal Rounds ---
    for (var i = 0; i < R_P; i++) {
        arc[r] = AddRoundConstants(t);
        arc[r].state <== state[r];
        for(var k=0; k<t; k++) arc[r].C[k] <== round_constants[r][k];
        
        sboxes[sbox_c] = Sbox();
        sboxes[sbox_c].x <== arc[r].out[0];
        sbox_outputs[r][0] <== sboxes[sbox_c].out;
        sbox_c++;
        for (var k = 1; k < t; k++) {
            sbox_outputs[r][k] <== arc[r].out[k];
        }

        mat_int[mat_int_c] = InternalMatrix(t);
        mat_int[mat_int_c].state <== sbox_outputs[r];
        state[r+1] <== mat_int[mat_int_c].out;
        mat_int_c++;
        r++;
    }

    // --- Final External Rounds ---
    for (var i = 0; i < R_F / 2; i++) {
        arc[r] = AddRoundConstants(t);
        arc[r].state <== state[r];
        for(var k=0; k<t; k++) arc[r].C[k] <== round_constants[r][k];

        for (var k = 0; k < t; k++) {
            sboxes[sbox_c] = Sbox();
            sboxes[sbox_c].x <== arc[r].out[k];
            sbox_outputs[r][k] <== sboxes[sbox_c].out;
            sbox_c++;
        }

        mat_ext[mat_ext_c] = ExternalMatrix(t);
        mat_ext[mat_ext_c].state <== sbox_outputs[r];
        for(var k=0; k<t; k++) for(var l=0; l<t; l++) mat_ext[mat_ext_c].M[k][l] <== M_E[k][l];
        
        state[r+1] <== mat_ext[mat_ext_c].out;
        mat_ext_c++;
        r++;
    }

    out <== state[NUM_ROUNDS][0];
}


/*
 * ==========================================================
 * Main Circuit Template
 * ==========================================================
 */
template Main() {
    signal input hash;
    signal input preImage[2];
    signal input round_constants[30][3];
    signal input M_E[3][3];

    component hasher = Poseidon2(3, 8, 22);

    hasher.in[0] <== preImage[0];
    hasher.in[1] <== preImage[1];

    for (var i=0; i<30; i++) {
        for (var j=0; j<3; j++) {
            hasher.round_constants[i][j] <== round_constants[i][j];
        }
    }
    for (var i=0; i<3; i++) {
        for (var j=0; j<3; j++) {
            hasher.M_E[i][j] <== M_E[i][j];
        }
    }

    hash === hasher.out;
}

/*
 * ==========================================================
 * Instantiate the Main Component
 * ==========================================================
 */
component main { public [ hash ] } = Main();
