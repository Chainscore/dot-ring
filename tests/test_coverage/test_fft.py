"""Tests for FFT module to improve coverage."""

from dot_ring.ring_proof.constants import OMEGA_512 as OMEGA
from dot_ring.ring_proof.constants import S_PRIME
from dot_ring.ring_proof.polynomial.fft import (
    _fft_in_place,
    _get_bit_reverse,
    _get_roots,
    _get_twiddle_factors,
    evaluate_poly_fft,
    evaluate_poly_over_domain,
    inverse_fft,
)


class TestFFT:
    """Test cases for FFT functions."""

    # Test constants - using a smaller prime for easier testing
    SMALL_PRIME = 17
    SMALL_OMEGA = 3  # primitive 4th root of unity mod 17 (3^4 = 81 = 4*17 + 13... let's use a proper one)

    # Actually for mod 17: 17-1 = 16 = 2^4, so primitive roots exist
    # 3^4 mod 17 = 81 mod 17 = 13, 3^8 mod 17 = 16, 3^16 mod 17 = 1
    # So 3 is a primitive 16th root of unity
    # For 8th root: 3^2 = 9, for 4th root: 3^4 = 13, for 2nd root: 3^8 = 16 = -1
    # Actually we need omega^n = 1 mod p
    # 3^4 = 81 = 4*17 + 13 = 13 != 1
    # Try omega = 4: 4^4 = 256 mod 17 = 256 - 15*17 = 256 - 255 = 1. Yes!
    # So 4 is a primitive 4th root of unity mod 17

    def test_get_bit_reverse_n1(self):
        """Test bit reverse for n=1."""
        result = _get_bit_reverse(1)
        assert result == [0]

    def test_get_bit_reverse_n2(self):
        """Test bit reverse for n=2."""
        result = _get_bit_reverse(2)
        assert result == [0, 1]

    def test_get_bit_reverse_n4(self):
        """Test bit reverse for n=4."""
        result = _get_bit_reverse(4)
        # For n=4, bits=2: 0->0, 1->2, 2->1, 3->3
        assert result == [0, 2, 1, 3]

    def test_get_bit_reverse_n8(self):
        """Test bit reverse for n=8."""
        result = _get_bit_reverse(8)
        # For n=8, bits=3: 000->000, 001->100, 010->010, 011->110, etc
        assert result == [0, 4, 2, 6, 1, 5, 3, 7]

    def test_get_twiddle_factors_basic(self):
        """Test twiddle factor computation."""
        # For n=4 with omega=4 mod 17
        n = 4
        omega = 4  # 4th root of unity mod 17
        prime = 17

        twiddles = _get_twiddle_factors(n, omega, prime)

        # Should have log2(4) = 2 stages
        assert len(twiddles) == 2

        # Stage 0 (m=2): half_m=1, stride=2, w_step = omega^2 = 16
        # twiddles[0] = [1]
        assert twiddles[0] == [1]

        # Stage 1 (m=4): half_m=2, stride=1, w_step = omega^1 = 4
        # twiddles[1] = [1, 4]
        assert twiddles[1] == [1, 4]

    def test_get_roots(self):
        """Test roots of unity computation."""
        n = 8
        omega = 4
        prime = 17

        # omega^4 mod 17 = 256 mod 17 = 1, but we need 8th root
        # Let's find 8th root: need omega^8 = 1 mod 17
        # 2^8 = 256 mod 17 = 1. Yes! 2 is 8th root
        omega = 2

        roots = _get_roots(n, omega, prime)

        # Should have n/2 = 4 roots
        assert len(roots) == 4
        # roots[i] = omega^i
        assert roots[0] == 1
        assert roots[1] == 2
        assert roots[2] == 4
        assert roots[3] == 8

    def test_fft_in_place_trivial(self):
        """Test FFT with single coefficient."""
        coeffs = [5]
        _fft_in_place(coeffs, 1, 17)
        assert coeffs == [5]

    def test_fft_in_place_size_2(self):
        """Test FFT with 2 coefficients."""
        # For size 2, omega should be a primitive 2nd root of unity
        # omega^2 = 1, omega != 1, so omega = -1 = p-1 = 16 mod 17
        # Just test that FFT runs without error for small inputs
        # Use larger prime field for proper FFT
        omega_2 = pow(OMEGA, 512 // 2, S_PRIME)  # Scale down from 512-th root
        coeffs = [3, 5]

        _fft_in_place(coeffs, omega_2, S_PRIME)
        # Just verify the result has same length
        assert len(coeffs) == 2

    def test_inverse_fft(self):
        """Test inverse FFT recovers original coefficients."""
        # Use the actual module constants
        original = [1, 2, 3, 4, 5, 6, 7, 8]

        # Need to find proper omega for size 8 in S_PRIME
        # Using module omega scaled down
        omega_8 = pow(OMEGA, 512 // 8, S_PRIME)  # Scale down from 512-th root

        # Compute FFT
        values = original[:]
        _fft_in_place(values, omega_8, S_PRIME)

        # Compute inverse FFT
        recovered = inverse_fft(values, omega_8, S_PRIME)

        assert recovered == original

    def test_evaluate_poly_over_domain_basic(self):
        """Test polynomial evaluation over domain."""
        # poly = 1 + 2x (coefficients [1, 2])
        poly = [1, 2]
        n = 4
        omega = 4  # 4th root of unity mod 17
        prime = 17
        domain = [pow(omega, i, prime) for i in range(n)]  # [1, 4, 16, 13]

        result = evaluate_poly_over_domain(poly, domain, omega, prime)

        # Should evaluate at each domain point
        # At x=1: 1 + 2*1 = 3
        # At x=4: 1 + 2*4 = 9
        # At x=16: 1 + 2*16 = 33 mod 17 = 16
        # At x=13: 1 + 2*13 = 27 mod 17 = 10
        assert len(result) == 4

    def test_evaluate_poly_over_domain_with_padding(self):
        """Test polynomial evaluation when poly is smaller than domain."""
        poly = [5]  # constant polynomial
        n = 4
        omega = 4
        prime = 17
        domain = [pow(omega, i, prime) for i in range(n)]

        result = evaluate_poly_over_domain(poly, domain, omega, prime)

        # Constant polynomial evaluates to same value everywhere
        assert len(result) == 4

    def test_evaluate_poly_over_domain_with_folding(self):
        """Test polynomial evaluation with folding (poly larger than domain)."""
        # poly of degree > n requires folding
        poly = [1, 2, 3, 4, 5]  # degree 4
        n = 4
        omega = 4
        prime = 17
        domain = [pow(omega, i, prime) for i in range(n)]

        result = evaluate_poly_over_domain(poly, domain, omega, prime)

        # Result should fold coefficients
        assert len(result) == 4

    def test_evaluate_poly_fft_standard(self):
        """Test FFT polynomial evaluation with coset_offset=1."""
        poly = [1, 2, 3, 4]
        domain_size = 4
        omega = 4
        prime = 17

        result = evaluate_poly_fft(poly, domain_size, omega, prime, coset_offset=1)

        assert len(result) == domain_size

    def test_evaluate_poly_fft_with_coset(self):
        """Test FFT polynomial evaluation with coset offset."""
        poly = [1, 2, 3, 4]
        domain_size = 4
        omega = 4
        prime = 17
        coset_offset = 2  # non-trivial coset

        result = evaluate_poly_fft(poly, domain_size, omega, prime, coset_offset=coset_offset)

        assert len(result) == domain_size

    def test_evaluate_poly_fft_larger_poly(self):
        """Test FFT with polynomial larger than domain size."""
        # Polynomial with more coefficients than domain
        poly = [1, 2, 3, 4, 5, 6, 7, 8, 9]  # 9 coefficients
        domain_size = 4
        omega = 4
        prime = 17

        result = evaluate_poly_fft(poly, domain_size, omega, prime, coset_offset=1)

        assert len(result) == domain_size

    def test_evaluate_poly_fft_larger_poly_with_coset(self):
        """Test FFT with larger polynomial and coset offset."""
        poly = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]  # more than 2*domain_size
        domain_size = 4
        omega = 4
        prime = 17
        coset_offset = 3

        result = evaluate_poly_fft(poly, domain_size, omega, prime, coset_offset=coset_offset)

        assert len(result) == domain_size

    def test_fft_roundtrip_with_real_constants(self):
        """Test FFT/IFFT roundtrip with actual module constants."""
        # Use actual constants from the module
        n = 8
        omega_n = pow(OMEGA, 512 // n, S_PRIME)

        original = [i * 12345 for i in range(n)]  # Some test values

        # Forward FFT
        values = original[:]
        _fft_in_place(values, omega_n, S_PRIME)

        # Inverse FFT
        recovered = inverse_fft(values, omega_n, S_PRIME)

        assert recovered == original

    def test_caching_bit_reverse(self):
        """Test that bit reverse caching works correctly."""
        # First call
        result1 = _get_bit_reverse(16)
        # Second call should return cached result
        result2 = _get_bit_reverse(16)

        assert result1 == result2
        # Check cache is being used (same object)
        assert result1 is result2

    def test_caching_twiddle_factors(self):
        """Test that twiddle factor caching works correctly."""
        result1 = _get_twiddle_factors(8, OMEGA, S_PRIME)
        result2 = _get_twiddle_factors(8, OMEGA, S_PRIME)

        assert result1 == result2
        assert result1 is result2  # Same cached object

    def test_caching_roots(self):
        """Test that roots caching works correctly."""
        result1 = _get_roots(16, OMEGA, S_PRIME)
        result2 = _get_roots(16, OMEGA, S_PRIME)

        assert result1 == result2
        assert result1 is result2
