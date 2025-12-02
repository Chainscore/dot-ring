# cython: language_level=3
# cython: boundscheck=False
# cython: wraparound=False
# cython: cdivision=True
# cython: initializedcheck=False
# cython: language_level=3
# cython: boundscheck=False
# cython: wraparound=False
# cython: cdivision=True
# cython: initializedcheck=False

from libc.stdlib cimport malloc, free
from dot_ring.curve.native_field.scalar cimport Scalar, bls_scalar_t, bls_scalar_ntt_round

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
        Py_ssize_t i, stage, m, half_m
        bls_scalar_t *coeffs_c
        bls_scalar_t *twiddles_c
        list stage_twiddles_list
        object val
        Scalar s
    
    if n == 1:
        return

    # Allocate memory for coefficients
    coeffs_c = <bls_scalar_t *>malloc(n * sizeof(bls_scalar_t))
    if not coeffs_c:
        raise MemoryError()

    try:
        # Convert coefficients to C array and apply bit-reverse permutation simultaneously
        for i in range(n):
            val = coeffs[rev[i]]
            if isinstance(val, Scalar):
                coeffs_c[i] = (<Scalar>val).val
            else:
                coeffs_c[i] = Scalar(val).val
        
        # Cooley-Tukey butterfly stages
        stage = 0
        m = 2
        while m <= n:
            half_m = m >> 1
            stage_twiddles_list = twiddles[stage]
            
            # Allocate and convert twiddles for this stage
            twiddles_c = <bls_scalar_t *>malloc(half_m * sizeof(bls_scalar_t))
            if not twiddles_c:
                raise MemoryError()
            
            try:
                for i in range(half_m):
                    val = stage_twiddles_list[i]
                    if isinstance(val, Scalar):
                        twiddles_c[i] = (<Scalar>val).val
                    else:
                        twiddles_c[i] = Scalar(val).val
                
                # Perform NTT round in C
                bls_scalar_ntt_round(coeffs_c, n, twiddles_c, m)
                
            finally:
                free(twiddles_c)
            
            m <<= 1
            stage += 1
        
        # Convert back to Python integers (or Scalars if preferred, but existing code expects ints)
        for i in range(n):
            # Create a temporary Scalar to convert back to int/mpz
            # Or better, expose a C function to convert bls_scalar_t to python int directly?
            # For now, use Scalar wrapper overhead.
            s = Scalar.__new__(Scalar)
            s.val = coeffs_c[i]
            coeffs[i] = int(s) 
            
    finally:
        free(coeffs_c)