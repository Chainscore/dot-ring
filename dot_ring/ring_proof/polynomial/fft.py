"""FFT-based polynomial evaluation over evaluation domains.

This module provides efficient O(n log n) polynomial evaluation over
structured domains using the Number Theoretic Transform (NTT), replacing
the naive O(n * m) Horner evaluation.
"""

from functools import lru_cache
from typing import List

# Cython-based FTT
from dot_ring.ring_proof.polynomial.ntt import ntt_in_place


@lru_cache(maxsize=None)
def _get_bit_reverse(n: int) -> List[int]:
    """Get precomputed bit-reversal permutation indices."""
    bits = n.bit_length() - 1
    rev_indices = [0] * n
    for i in range(n):
        r = 0
        val = i
        for _ in range(bits):
            r = (r << 1) | (val & 1)
            val >>= 1
        rev_indices[i] = r

    return rev_indices

@lru_cache(maxsize=None)
def _get_twiddle_factors(n: int, omega: int, prime: int) -> List[List[int]]:
    """Get precomputed twiddle factors for all NTT stages.
    
    Returns a list where twiddles[stage] contains the twiddle factors for that stage.
    This is more cache-friendly than computing w = roots[j * stride] each time.
    """
    twiddles = []
    m = 2
    while m <= n:
        half_m = m >> 1
        stride = n // m
        
        # Compute twiddle factors for this stage
        stage_twiddles = [0] * half_m
        w = 1
        # w_step = omega^stride
        w_step = pow(omega, stride, prime)
        
        for j in range(half_m):
            stage_twiddles[j] = w
            w = (w * w_step) % prime
        
        twiddles.append(stage_twiddles)
        m <<= 1
    
    return twiddles

@lru_cache(maxsize=None)
def _get_roots(n: int, omega: int, prime: int) -> List[int]:
    """Get precomputed roots of unity (legacy, for compatibility)."""
    powers = [1] * (n // 2)
    curr = 1
    for i in range(1, n // 2):
        curr = (curr * omega) % prime
        powers[i] = curr

    return powers


def _fft_in_place(coeffs: List[int], omega: int, prime: int) -> None:
    """In-place Cooley-Tukey.

    Args:
        coeffs: Coefficient vector (will be modified in-place)
        omega: Primitive n-th root of unity mod prime
        prime: Field modulus
    """
    n = len(coeffs)
    if n == 1:
        return

    rev = _get_bit_reverse(n)
    twiddles = _get_twiddle_factors(n, omega, prime)

    ntt_in_place(coeffs, twiddles, rev, prime)
    return

def inverse_fft(values: List[int], omega: int, prime: int) -> List[int]:
    """Inverse FFT.
    
    Args:
        values: Point evaluations
        omega: Primitive n-th root of unity mod prime
        prime: Field modulus
        
    Returns:
        Polynomial coefficients
    """
    n = len(values)
    inv_omega = pow(omega, -1, prime)
    coeffs = values[:]
    _fft_in_place(coeffs, inv_omega, prime)
    inv_n = pow(n, -1, prime)
    return [(c * inv_n) % prime for c in coeffs]


def evaluate_poly_over_domain(
    poly: List[int], 
    domain: List[int], 
    omega: int, 
    prime: int
) -> List[int]:
    """Evaluate polynomial over a structured domain using FFT.
    
    Assumes domain = [omega^0, omega^1, ..., omega^(n-1)] mod prime.
    
    Args:
        poly: Polynomial coefficients (lowest degree first)
        domain: Evaluation domain (must be powers of omega)
        omega: Primitive n-th root of unity mod prime
        prime: Field modulus
        
    Returns:
        List of polynomial evaluations at each domain point
    """
    n = len(domain)
    
    # Pad or truncate coefficients to domain size
    # If poly has more coefficients than domain size, we need to reduce mod (X^n - 1)
    coeffs = poly[:] if len(poly) <= n else poly[:]
    
    # Reduce polynomial modulo X^n - 1 by folding coefficients
    if len(poly) > n:
        result = [0] * n
        for i, c in enumerate(poly):
            result[i % n] = (result[i % n] + c) % prime
        coeffs = result
    else:
        # Pad with zeros if needed
        coeffs = coeffs + [0] * (n - len(coeffs))
    
    # Perform FFT
    _fft_in_place(coeffs, omega, prime)
    
    return coeffs


def evaluate_poly_fft(
    poly: List[int], 
    domain_size: int,
    omega: int, 
    prime: int,
    coset_offset: int = 1
) -> List[int]:
    """Evaluate polynomial over a coset domain using FFT.
    
    Args:
        poly: Polynomial coefficients (lowest degree first)
        domain_size: Size of evaluation domain (must be power of 2)
        omega: Primitive domain_size-th root of unity mod prime
        prime: Field modulus
        coset_offset: Coset offset (1 for standard domain)
        
    Returns:
        List of polynomial evaluations over the domain/coset
    """
    n = domain_size
    
    # Reduce polynomial modulo X^n - coset_offset^n
    coeffs = [0] * n
    if coset_offset == 1:
        # Standard reduction mod X^n - 1
        for i, c in enumerate(poly):
            coeffs[i % n] = (coeffs[i % n] + c) % prime
    else:
        # Coset reduction: fold with offset powers
        chunk_idx = 0
        for chunk_start in range(0, len(poly), n):
            chunk = poly[chunk_start:chunk_start + n]
            if chunk_idx == 0:
                for i, c in enumerate(chunk):
                    coeffs[i] = c
            else:
                offset_power = pow(coset_offset, chunk_idx * n, prime)
                for i, c in enumerate(chunk):
                    coeffs[i] = (coeffs[i] + c * offset_power) % prime
            chunk_idx += 1
    
    # Apply FFT
    _fft_in_place(coeffs, omega, prime)
    
    return coeffs
