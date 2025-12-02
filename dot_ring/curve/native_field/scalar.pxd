# cython: language_level=3

from libc.stdint cimport uint64_t, uint8_t

cdef extern from "bls12_381_scalar.h":
    ctypedef struct bls_scalar_t:
        uint64_t val[4]
    
    void bls_scalar_from_uint64(bls_scalar_t *out, uint64_t in_)
    void bls_scalar_from_bytes(bls_scalar_t *out, const uint8_t *in_)
    void bls_scalar_to_bytes(uint8_t *out, const bls_scalar_t *in_)
    
    void bls_scalar_add(bls_scalar_t *out, const bls_scalar_t *a, const bls_scalar_t *b)
    void bls_scalar_sub(bls_scalar_t *out, const bls_scalar_t *a, const bls_scalar_t *b)
    void bls_scalar_mul_mont(bls_scalar_t *out, const bls_scalar_t *a, const bls_scalar_t *b)
    void bls_scalar_exp(bls_scalar_t *out, const bls_scalar_t *base, const bls_scalar_t *exp)
    void bls_scalar_inv(bls_scalar_t *out, const bls_scalar_t *in_)
    
    void bls_scalar_to_mont(bls_scalar_t *out, const bls_scalar_t *in_)
    void bls_scalar_from_mont(bls_scalar_t *out, const bls_scalar_t *in_)

    # Vector operations
    void bls_scalar_vec_add(bls_scalar_t *out, const bls_scalar_t *a, const bls_scalar_t *b, size_t n)
    void bls_scalar_vec_sub(bls_scalar_t *out, const bls_scalar_t *a, const bls_scalar_t *b, size_t n)
    void bls_scalar_vec_mul(bls_scalar_t *out, const bls_scalar_t *a, const bls_scalar_t *b, size_t n)
    void bls_scalar_vec_mul_scalar(bls_scalar_t *out, const bls_scalar_t *a, const bls_scalar_t *b, size_t n)
    void bls_scalar_vec_add_scalar(bls_scalar_t *out, const bls_scalar_t *a, const bls_scalar_t *b, size_t n)
    void bls_scalar_vec_sub_scalar(bls_scalar_t *out, const bls_scalar_t *a, const bls_scalar_t *b, size_t n)
    void bls_scalar_ntt_round(bls_scalar_t *coeffs, size_t n, const bls_scalar_t *twiddles, size_t m)

cdef class Scalar:
    cdef bls_scalar_t val
    @staticmethod
    cdef Scalar from_native(bls_scalar_t val)
