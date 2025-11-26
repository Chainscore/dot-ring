# cython: language_level=3
# cython: boundscheck=False
# cython: wraparound=False
# cython: cdivision=True
# cython: initializedcheck=False
from gmpy2 import mpz

def ntt_in_place(list coeffs, list twiddles, list rev, object prime):
    """
    Complete in-place NTT using precomputed twiddles and bit-reverse indices.
    
    Args:
        coeffs: Coefficient vector (modified in-place)
        twiddles: List of stage twiddle factors
        rev: Bit-reverse permutation indices
        prime: Field modulus
    """
    cdef:
        Py_ssize_t n = len(coeffs)
        Py_ssize_t i, stage, m, half_m, k, j, idx1, idx2
        list temp
        list stage_twiddles
        object w, t, u, p
    
    if n == 1:
        return
    
    # Use gmpy2 for faster modular arithmetic
    p = mpz(prime)
    # Convert coefficients to mpz for faster arithmetic
    for i in range(n):
        coeffs[i] = mpz(coeffs[i])
    
    # Bit-reverse permutation
    temp = [coeffs[rev[i]] for i in range(n)]
    for i in range(n):
        coeffs[i] = temp[i]
    
    # Cooley-Tukey butterfly stages
    stage = 0
    m = 2
    while m <= n:
        half_m = m >> 1
        stage_twiddles = twiddles[stage]
        
        k = 0
        while k < n:
            for j in range(half_m):
                w = stage_twiddles[j]
                idx1 = k + j
                idx2 = k + j + half_m
                
                t = (w * coeffs[idx2]) % p
                u = coeffs[idx1]
                
                coeffs[idx1] = (u + t) % p
                coeffs[idx2] = (u - t) % p
            k += m
        
        m <<= 1
        stage += 1
    
    # Convert back to int if using gmpy2
    for i in range(n):
        coeffs[i] = int(coeffs[i])