#include "bls12_381_scalar.h"
#include <string.h>

typedef __uint128_t uint128_t;

// Modulus P = 0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001
const bls_scalar_t BLS_SCALAR_MODULUS = {{
    0xFFFFFFFF00000001ULL,
    0x53BDA402FFFE5BFEULL,
    0x3339D80809A1D805ULL,
    0x73EDA753299D7D48ULL
}};

// R^2 mod P for Montgomery conversion
// R = 2^256
// R^2 mod P = (2^256)^2 mod P
// Calculated using Python: pow(2**256, 2, P)
const bls_scalar_t BLS_SCALAR_R2 = {{
    0xc999e990f3f29c6dULL,
    0x2b6cedcb87925c23ULL,
    0x05d314967254398fULL,
    0x0748d9d99f59ff11ULL
}};

// -P^-1 mod 2^64
// Calculated using Python: pow(-P, -1, 2**64)
const uint64_t BLS_SCALAR_INV = 0xfffffffeffffffffULL;

// Helper: Add with carry
static inline uint64_t adc(uint64_t a, uint64_t b, uint64_t *carry) {
    uint128_t res = (uint128_t)a + b + *carry;
    *carry = (uint64_t)(res >> 64);
    return (uint64_t)res;
}

// Helper: Subtract with borrow
static inline uint64_t sbb(uint64_t a, uint64_t b, uint64_t *borrow) {
    uint128_t res = (uint128_t)a - b - *borrow;
    *borrow = (uint64_t)(res >> 127); // 1 if borrow occurred, 0 otherwise
    return (uint64_t)res;
}

void bls_scalar_add(bls_scalar_t *out, const bls_scalar_t *a, const bls_scalar_t *b) {
    uint64_t carry = 0;
    bls_scalar_t res;
    
    res.val[0] = adc(a->val[0], b->val[0], &carry);
    res.val[1] = adc(a->val[1], b->val[1], &carry);
    res.val[2] = adc(a->val[2], b->val[2], &carry);
    res.val[3] = adc(a->val[3], b->val[3], &carry);
    
    // Subtract modulus if result >= modulus
    // We can do this by attempting to subtract P and checking borrow
    bls_scalar_t tmp;
    uint64_t borrow = 0;
    tmp.val[0] = sbb(res.val[0], BLS_SCALAR_MODULUS.val[0], &borrow);
    tmp.val[1] = sbb(res.val[1], BLS_SCALAR_MODULUS.val[1], &borrow);
    tmp.val[2] = sbb(res.val[2], BLS_SCALAR_MODULUS.val[2], &borrow);
    tmp.val[3] = sbb(res.val[3], BLS_SCALAR_MODULUS.val[3], &borrow);
    
    // If borrow occurred (borrow=1), result was < P, so keep res.
    // If borrow=0, result was >= P, so use tmp.
    // Also need to account for the initial carry from addition.
    // If carry=1, result > 2^256 > P, so we definitely subtract P.
    
    // Logic:
    // If carry=1, we must subtract P. The result fits in 256 bits.
    // If carry=0, we subtract P only if res >= P.
    
    // Actually, simpler constant-time way:
    // mask = 0 if (res < P and carry=0) else 0xFF..FF
    // But let's stick to simple conditional move logic for now or just use the borrow.
    
    // If carry is set, we definitely wrap around.
    // If borrow is NOT set (meaning res >= P), we also wrap around.
    // So if (carry | !borrow), we use tmp.
    
    // Wait, sbb returns borrow=1 if a < b.
    // So if res < P, borrow=1.
    // We want to subtract P if res >= P. i.e., borrow=0.
    // BUT, if carry=1, then the real value is 2^256 + res.
    // 2^256 + res - P is the correct result.
    // The sbb above computes res - P.
    // If carry=1, then 2^256 + res - P = (2^256 - P) + res.
    // This is getting complicated to explain but standard practice:
    // If carry=1, we need the result of the subtraction.
    // If carry=0, we need the result of subtraction ONLY IF borrow=0.
    
    bool use_sub = carry || (borrow == 0);
    
    for(int i=0; i<4; i++) {
        out->val[i] = use_sub ? tmp.val[i] : res.val[i];
    }
}

void bls_scalar_sub(bls_scalar_t *out, const bls_scalar_t *a, const bls_scalar_t *b) {
    uint64_t borrow = 0;
    bls_scalar_t res;
    
    res.val[0] = sbb(a->val[0], b->val[0], &borrow);
    res.val[1] = sbb(a->val[1], b->val[1], &borrow);
    res.val[2] = sbb(a->val[2], b->val[2], &borrow);
    res.val[3] = sbb(a->val[3], b->val[3], &borrow);
    
    // If borrow occurred, we need to add P back.
    // res = res + P (mod 2^256)
    
    uint64_t carry = 0;
    bls_scalar_t tmp;
    tmp.val[0] = adc(res.val[0], BLS_SCALAR_MODULUS.val[0], &carry);
    tmp.val[1] = adc(res.val[1], BLS_SCALAR_MODULUS.val[1], &carry);
    tmp.val[2] = adc(res.val[2], BLS_SCALAR_MODULUS.val[2], &carry);
    tmp.val[3] = adc(res.val[3], BLS_SCALAR_MODULUS.val[3], &carry);
    
    for(int i=0; i<4; i++) {
        out->val[i] = borrow ? tmp.val[i] : res.val[i];
    }
}

// Montgomery Multiplication (CIOS method)
void bls_scalar_mul_mont(bls_scalar_t *out, const bls_scalar_t *a, const bls_scalar_t *b) {
    // Unrolled CIOS method
    uint64_t r[5] = {0};
    uint64_t u, m, carry;
    uint128_t prod;

    // i = 0
    {
        u = 0;
        // j = 0
        prod = (uint128_t)a->val[0] * b->val[0] + r[0] + u; r[0] = (uint64_t)prod; u = (uint64_t)(prod >> 64);
        // j = 1
        prod = (uint128_t)a->val[1] * b->val[0] + r[1] + u; r[1] = (uint64_t)prod; u = (uint64_t)(prod >> 64);
        // j = 2
        prod = (uint128_t)a->val[2] * b->val[0] + r[2] + u; r[2] = (uint64_t)prod; u = (uint64_t)(prod >> 64);
        // j = 3
        prod = (uint128_t)a->val[3] * b->val[0] + r[3] + u; r[3] = (uint64_t)prod; u = (uint64_t)(prod >> 64);
        
        r[4] = u;

        m = r[0] * BLS_SCALAR_INV;
        
        prod = (uint128_t)m * BLS_SCALAR_MODULUS.val[0] + r[0]; carry = (uint64_t)(prod >> 64);
        prod = (uint128_t)m * BLS_SCALAR_MODULUS.val[1] + r[1] + carry; r[0] = (uint64_t)prod; carry = (uint64_t)(prod >> 64);
        prod = (uint128_t)m * BLS_SCALAR_MODULUS.val[2] + r[2] + carry; r[1] = (uint64_t)prod; carry = (uint64_t)(prod >> 64);
        prod = (uint128_t)m * BLS_SCALAR_MODULUS.val[3] + r[3] + carry; r[2] = (uint64_t)prod; carry = (uint64_t)(prod >> 64);
        
        prod = (uint128_t)r[4] + carry; r[3] = (uint64_t)prod; r[4] = (uint64_t)(prod >> 64);
    }

    // i = 1
    {
        u = 0;
        prod = (uint128_t)a->val[0] * b->val[1] + r[0] + u; r[0] = (uint64_t)prod; u = (uint64_t)(prod >> 64);
        prod = (uint128_t)a->val[1] * b->val[1] + r[1] + u; r[1] = (uint64_t)prod; u = (uint64_t)(prod >> 64);
        prod = (uint128_t)a->val[2] * b->val[1] + r[2] + u; r[2] = (uint64_t)prod; u = (uint64_t)(prod >> 64);
        prod = (uint128_t)a->val[3] * b->val[1] + r[3] + u; r[3] = (uint64_t)prod; u = (uint64_t)(prod >> 64);
        
        prod = (uint128_t)r[4] + u; r[4] = (uint64_t)prod;

        m = r[0] * BLS_SCALAR_INV;
        
        prod = (uint128_t)m * BLS_SCALAR_MODULUS.val[0] + r[0]; carry = (uint64_t)(prod >> 64);
        prod = (uint128_t)m * BLS_SCALAR_MODULUS.val[1] + r[1] + carry; r[0] = (uint64_t)prod; carry = (uint64_t)(prod >> 64);
        prod = (uint128_t)m * BLS_SCALAR_MODULUS.val[2] + r[2] + carry; r[1] = (uint64_t)prod; carry = (uint64_t)(prod >> 64);
        prod = (uint128_t)m * BLS_SCALAR_MODULUS.val[3] + r[3] + carry; r[2] = (uint64_t)prod; carry = (uint64_t)(prod >> 64);
        
        prod = (uint128_t)r[4] + carry; r[3] = (uint64_t)prod; r[4] = (uint64_t)(prod >> 64);
    }

    // i = 2
    {
        u = 0;
        prod = (uint128_t)a->val[0] * b->val[2] + r[0] + u; r[0] = (uint64_t)prod; u = (uint64_t)(prod >> 64);
        prod = (uint128_t)a->val[1] * b->val[2] + r[1] + u; r[1] = (uint64_t)prod; u = (uint64_t)(prod >> 64);
        prod = (uint128_t)a->val[2] * b->val[2] + r[2] + u; r[2] = (uint64_t)prod; u = (uint64_t)(prod >> 64);
        prod = (uint128_t)a->val[3] * b->val[2] + r[3] + u; r[3] = (uint64_t)prod; u = (uint64_t)(prod >> 64);
        
        prod = (uint128_t)r[4] + u; r[4] = (uint64_t)prod;

        m = r[0] * BLS_SCALAR_INV;
        
        prod = (uint128_t)m * BLS_SCALAR_MODULUS.val[0] + r[0]; carry = (uint64_t)(prod >> 64);
        prod = (uint128_t)m * BLS_SCALAR_MODULUS.val[1] + r[1] + carry; r[0] = (uint64_t)prod; carry = (uint64_t)(prod >> 64);
        prod = (uint128_t)m * BLS_SCALAR_MODULUS.val[2] + r[2] + carry; r[1] = (uint64_t)prod; carry = (uint64_t)(prod >> 64);
        prod = (uint128_t)m * BLS_SCALAR_MODULUS.val[3] + r[3] + carry; r[2] = (uint64_t)prod; carry = (uint64_t)(prod >> 64);
        
        prod = (uint128_t)r[4] + carry; r[3] = (uint64_t)prod; r[4] = (uint64_t)(prod >> 64);
    }

    // i = 3
    {
        u = 0;
        prod = (uint128_t)a->val[0] * b->val[3] + r[0] + u; r[0] = (uint64_t)prod; u = (uint64_t)(prod >> 64);
        prod = (uint128_t)a->val[1] * b->val[3] + r[1] + u; r[1] = (uint64_t)prod; u = (uint64_t)(prod >> 64);
        prod = (uint128_t)a->val[2] * b->val[3] + r[2] + u; r[2] = (uint64_t)prod; u = (uint64_t)(prod >> 64);
        prod = (uint128_t)a->val[3] * b->val[3] + r[3] + u; r[3] = (uint64_t)prod; u = (uint64_t)(prod >> 64);
        
        prod = (uint128_t)r[4] + u; r[4] = (uint64_t)prod;

        m = r[0] * BLS_SCALAR_INV;
        
        prod = (uint128_t)m * BLS_SCALAR_MODULUS.val[0] + r[0]; carry = (uint64_t)(prod >> 64);
        prod = (uint128_t)m * BLS_SCALAR_MODULUS.val[1] + r[1] + carry; r[0] = (uint64_t)prod; carry = (uint64_t)(prod >> 64);
        prod = (uint128_t)m * BLS_SCALAR_MODULUS.val[2] + r[2] + carry; r[1] = (uint64_t)prod; carry = (uint64_t)(prod >> 64);
        prod = (uint128_t)m * BLS_SCALAR_MODULUS.val[3] + r[3] + carry; r[2] = (uint64_t)prod; carry = (uint64_t)(prod >> 64);
        
        prod = (uint128_t)r[4] + carry; r[3] = (uint64_t)prod; r[4] = (uint64_t)(prod >> 64);
    }
    
    // Final subtraction
    bls_scalar_t tmp;
    uint64_t borrow = 0;
    tmp.val[0] = sbb(r[0], BLS_SCALAR_MODULUS.val[0], &borrow);
    tmp.val[1] = sbb(r[1], BLS_SCALAR_MODULUS.val[1], &borrow);
    tmp.val[2] = sbb(r[2], BLS_SCALAR_MODULUS.val[2], &borrow);
    tmp.val[3] = sbb(r[3], BLS_SCALAR_MODULUS.val[3], &borrow);
    
    bool use_sub = (r[4] != 0) || (borrow == 0);
    
    out->val[0] = use_sub ? tmp.val[0] : r[0];
    out->val[1] = use_sub ? tmp.val[1] : r[1];
    out->val[2] = use_sub ? tmp.val[2] : r[2];
    out->val[3] = use_sub ? tmp.val[3] : r[3];
}

void bls_scalar_to_mont(bls_scalar_t *out, const bls_scalar_t *in) {
    bls_scalar_mul_mont(out, in, &BLS_SCALAR_R2);
}

void bls_scalar_from_mont(bls_scalar_t *out, const bls_scalar_t *in) {
    // Multiply by 1 in Montgomery form (which is just R^-1 mod P in normal form? No.)
    // Montgomery mul: out = a * b * R^-1
    // If we want a * R^-1, we set b = 1.
    bls_scalar_t one = {{1, 0, 0, 0}};
    bls_scalar_mul_mont(out, in, &one);
}

// Montgomery Squaring (just wrapper around mul for now)
void bls_scalar_sqr_mont(bls_scalar_t *out, const bls_scalar_t *a) {
    bls_scalar_mul_mont(out, a, a);
}

// Modular Exponentiation (Square and Multiply)
// base should be in Montgomery form
// exp is a standard integer (scalar)
// result is in Montgomery form
void bls_scalar_exp(bls_scalar_t *out, const bls_scalar_t *base, const bls_scalar_t *exp) {
    // res = 1 (in Montgomery form, i.e., R mod P)
    bls_scalar_t res = BLS_SCALAR_R2; // R^2 * 1 * R^-1 = R
    // Wait, R2 is R^2. 1 in Mont is 1 * R.
    // My mul_mont(a, b) computes a * b * R^-1.
    // If I want 1 in Mont, I need 1 * R.
    // R2 is R^2.
    // mul_mont(R2, 1) = R^2 * 1 * R^-1 = R.
    // So yes, to get 1_Mont, I can use mul_mont(R2, 1).
    // Or just precompute R.
    // Let's compute 1_Mont dynamically for now to be safe.
    bls_scalar_t one = {{1, 0, 0, 0}};
    bls_scalar_to_mont(&res, &one);
    
    bls_scalar_t base_copy = *base;
    
    for (int i = 0; i < 4; i++) {
        uint64_t w = exp->val[i];
        for (int j = 0; j < 64; j++) {
            if (w & 1) {
                bls_scalar_mul_mont(&res, &res, &base_copy);
            }
            bls_scalar_sqr_mont(&base_copy, &base_copy);
            w >>= 1;
        }
    }
    *out = res;
}

// Modular Inverse using Fermat's Little Theorem: a^(p-2)
void bls_scalar_inv(bls_scalar_t *out, const bls_scalar_t *in) {
    // exp = P - 2
    bls_scalar_t exp = BLS_SCALAR_MODULUS;
    
    // Subtract 2
    uint64_t borrow = 0;
    exp.val[0] = sbb(exp.val[0], 2, &borrow);
    exp.val[1] = sbb(exp.val[1], 0, &borrow);
    exp.val[2] = sbb(exp.val[2], 0, &borrow);
    exp.val[3] = sbb(exp.val[3], 0, &borrow);
    
    bls_scalar_exp(out, in, &exp);
}

void bls_scalar_from_uint64(bls_scalar_t *out, uint64_t in) {
    out->val[0] = in;
    out->val[1] = 0;
    out->val[2] = 0;
    out->val[3] = 0;
}

void bls_scalar_from_bytes(bls_scalar_t *out, const uint8_t *in) {
    for (int i = 0; i < 4; i++) {
        uint64_t w = 0;
        for (int j = 0; j < 8; j++) {
            w |= ((uint64_t)in[i*8 + j]) << (j*8);
        }
        out->val[i] = w;
    }
}

void bls_scalar_to_bytes(uint8_t *out, const bls_scalar_t *in) {
    for (int i = 0; i < 4; i++) {
        uint64_t w = in->val[i];
        for (int j = 0; j < 8; j++) {
            out[i*8 + j] = (uint8_t)(w >> (j*8));
        }
    }
}

// Vector Operations
// These are designed to be auto-vectorized by the compiler (e.g. clang/gcc with -O3 -march=native)

void bls_scalar_vec_add(bls_scalar_t *out, const bls_scalar_t *a, const bls_scalar_t *b, size_t n) {
    for (size_t i = 0; i < n; i++) {
        bls_scalar_add(&out[i], &a[i], &b[i]);
    }
}

void bls_scalar_vec_sub(bls_scalar_t *out, const bls_scalar_t *a, const bls_scalar_t *b, size_t n) {
    for (size_t i = 0; i < n; i++) {
        bls_scalar_sub(&out[i], &a[i], &b[i]);
    }
}

void bls_scalar_vec_mul(bls_scalar_t *out, const bls_scalar_t *a, const bls_scalar_t *b, size_t n) {
    for (size_t i = 0; i < n; i++) {
        bls_scalar_mul_mont(&out[i], &a[i], &b[i]);
    }
}

void bls_scalar_vec_mul_scalar(bls_scalar_t *out, const bls_scalar_t *a, const bls_scalar_t *b, size_t n) {
    // b is a pointer to a single scalar, but we treat it as invariant in the loop
    const bls_scalar_t scalar = *b;
    for (size_t i = 0; i < n; i++) {
        bls_scalar_mul_mont(&out[i], &a[i], &scalar);
    }
}

void bls_scalar_vec_add_scalar(bls_scalar_t *out, const bls_scalar_t *a, const bls_scalar_t *b, size_t n) {
    const bls_scalar_t scalar = *b;
    for (size_t i = 0; i < n; i++) {
        bls_scalar_add(&out[i], &a[i], &scalar);
    }
}

void bls_scalar_vec_sub_scalar(bls_scalar_t *out, const bls_scalar_t *a, const bls_scalar_t *b, size_t n) {
    const bls_scalar_t scalar = *b;
    for (size_t i = 0; i < n; i++) {
        bls_scalar_sub(&out[i], &a[i], &scalar);
    }
}

// NTT Round
// Performs one stage of Cooley-Tukey NTT
// coeffs: array of size n
// twiddles: array of size m/2 (for this stage)
// m: current block size (2, 4, 8, ...)
void bls_scalar_ntt_round(bls_scalar_t *coeffs, size_t n, const bls_scalar_t *twiddles, size_t m) {
    size_t half_m = m >> 1;
    
    // Iterate over blocks of size m
    for (size_t k = 0; k < n; k += m) {
        // Iterate within block (butterfly operations)
        // This inner loop is the target for vectorization
        for (size_t j = 0; j < half_m; j++) {
            bls_scalar_t w = twiddles[j];
            bls_scalar_t *u = &coeffs[k + j];
            bls_scalar_t *v = &coeffs[k + j + half_m];
            bls_scalar_t t;
            
            // t = w * v
            bls_scalar_mul_mont(&t, &w, v);
            
            // v = u - t
            bls_scalar_sub(v, u, &t);
            
            // u = u + t
            bls_scalar_add(u, u, &t);
        }
    }
}
