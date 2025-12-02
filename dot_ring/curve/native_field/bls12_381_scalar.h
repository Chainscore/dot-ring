#ifndef BLS12_381_SCALAR_H
#define BLS12_381_SCALAR_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

// 256-bit integer represented as 4 64-bit words (little-endian)
typedef struct {
    uint64_t val[4];
} bls_scalar_t;

// Constants
extern const bls_scalar_t BLS_SCALAR_MODULUS;
extern const bls_scalar_t BLS_SCALAR_R2; // R^2 mod P for Montgomery conversion
extern const uint64_t BLS_SCALAR_INV;    // -P^-1 mod 2^64

// Core operations
void bls_scalar_from_uint64(bls_scalar_t *out, uint64_t in);
void bls_scalar_from_bytes(bls_scalar_t *out, const uint8_t *in);
void bls_scalar_to_bytes(uint8_t *out, const bls_scalar_t *in);

void bls_scalar_add(bls_scalar_t *out, const bls_scalar_t *a, const bls_scalar_t *b);
void bls_scalar_sub(bls_scalar_t *out, const bls_scalar_t *a, const bls_scalar_t *b);
void bls_scalar_mul_mont(bls_scalar_t *out, const bls_scalar_t *a, const bls_scalar_t *b); // Montgomery multiplication
void bls_scalar_sqr_mont(bls_scalar_t *out, const bls_scalar_t *a); // Montgomery squaring
void bls_scalar_exp(bls_scalar_t *out, const bls_scalar_t *base, const bls_scalar_t *exp); // Modular exponentiation
void bls_scalar_inv(bls_scalar_t *out, const bls_scalar_t *in); // Modular inverse

// Conversion
void bls_scalar_to_mont(bls_scalar_t *out, const bls_scalar_t *in);
void bls_scalar_from_mont(bls_scalar_t *out, const bls_scalar_t *in);

// Vector operations (SIMD-friendly)
void bls_scalar_vec_add(bls_scalar_t *out, const bls_scalar_t *a, const bls_scalar_t *b, size_t n);
void bls_scalar_vec_sub(bls_scalar_t *out, const bls_scalar_t *a, const bls_scalar_t *b, size_t n);
void bls_scalar_vec_mul(bls_scalar_t *out, const bls_scalar_t *a, const bls_scalar_t *b, size_t n);
void bls_scalar_vec_mul_scalar(bls_scalar_t *out, const bls_scalar_t *a, const bls_scalar_t *b, size_t n); // b is a single scalar broadcasted
void bls_scalar_vec_add_scalar(bls_scalar_t *out, const bls_scalar_t *a, const bls_scalar_t *b, size_t n);
void bls_scalar_vec_sub_scalar(bls_scalar_t *out, const bls_scalar_t *a, const bls_scalar_t *b, size_t n);

// NTT operations
void bls_scalar_ntt_round(bls_scalar_t *coeffs, size_t n, const bls_scalar_t *twiddles, size_t m);

#endif // BLS12_381_SCALAR_H
