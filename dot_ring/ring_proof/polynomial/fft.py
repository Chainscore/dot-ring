"""FFT-based polynomial evaluation over evaluation domains.

This module provides efficient O(n log n) polynomial evaluation over
structured domains using the Fast Fourier Transform (NTT), replacing
the naive O(n * m) Horner evaluation.
"""

from typing import List


def _bitreverse_copy(a: List[int], n: int) -> List[int]:
    """Reorder array elements by bit-reversing their indices."""
    result = [0] * n
    bits = n.bit_length() - 1
    for i in range(n):
        rev = int(bin(i)[2:].zfill(bits)[::-1], 2)
        result[rev] = a[i] if i < len(a) else 0
    return result


def _fft_in_place(coeffs: List[int], omega: int, prime: int) -> None:
    """In-place Cooley-Tukey FFT (radix-2 decimation-in-time).
    
    Args:
        coeffs: Coefficient vector (will be modified in-place)
        omega: Primitive n-th root of unity mod prime
        prime: Field modulus
    """
    n = len(coeffs)
    if n == 1:
        return
    
    # Bit-reverse permutation
    bits = n.bit_length() - 1
    for i in range(n):
        rev = int(bin(i)[2:].zfill(bits)[::-1], 2)
        if i < rev:
            coeffs[i], coeffs[rev] = coeffs[rev], coeffs[i]
    
    # Cooley-Tukey butterfly
    m = 2
    while m <= n:
        # omega_m is the m-th root of unity
        omega_m = pow(omega, n // m, prime)
        for k in range(0, n, m):
            omega_power = 1
            for j in range(m // 2):
                t = (omega_power * coeffs[k + j + m // 2]) % prime
                u = coeffs[k + j]
                coeffs[k + j] = (u + t) % prime
                coeffs[k + j + m // 2] = (u - t) % prime
                omega_power = (omega_power * omega_m) % prime
        m *= 2


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
