"""FFT-based polynomial evaluation over evaluation domains.

This module provides efficient O(n log n) polynomial evaluation over
structured domains using the Number Theoretic Transform (NTT), replacing
the naive O(n * m) Horner evaluation.
"""

from functools import lru_cache

from dot_ring.ring_proof.polynomial.ntt import BlsScalarNTTPlan


@lru_cache(maxsize=1024)
def _get_bit_reverse(n: int) -> list[int]:
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


@lru_cache(maxsize=1024)
def _get_twiddle_factors(n: int, omega: int, prime: int) -> list[list[int]]:
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


def _fft_in_place(coeffs: list[int], omega: int, prime: int) -> None:
    """In-place Cooley-Tukey.

    Args:
        coeffs: Coefficient vector (will be modified in-place)
        omega: Primitive n-th root of unity mod prime
        prime: Field modulus
    """
    n = len(coeffs)
    if n == 1:
        return

    BlsScalarNTTPlan(_get_twiddle_factors(n, omega, prime), _get_bit_reverse(n)).transform(coeffs)


def _fft_in_place_scaled(coeffs: list[int], omega: int, prime: int, scale: int) -> None:
    """In-place Cooley-Tukey followed by a scalar multiply on every output."""
    if scale == 1:
        _fft_in_place(coeffs, omega, prime)
        return

    n = len(coeffs)
    if n == 1:
        coeffs[0] = (coeffs[0] * scale) % prime
        return

    BlsScalarNTTPlan(_get_twiddle_factors(n, omega, prime), _get_bit_reverse(n)).transform_scaled(coeffs, scale)


def inverse_fft(values: list[int], omega: int, prime: int) -> list[int]:
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
    inv_n = pow(n, -1, prime)
    _fft_in_place_scaled(coeffs, inv_omega, prime, inv_n)
    return coeffs


def evaluate_poly_fft(poly: list[int], domain_size: int, omega: int, prime: int, coset_offset: int = 1) -> list[int]:
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
            chunk = poly[chunk_start : chunk_start + n]
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
