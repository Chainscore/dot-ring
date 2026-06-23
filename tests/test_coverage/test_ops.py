"""Tests for polynomial operations module to improve coverage."""

from dot_ring.ring_proof.params import RingProofParams
from dot_ring.ring_proof.polynomial.ops import (
    get_root_of_unity,
    lagrange_basis_polynomial,
    poly_add,
    poly_divide_by_vanishing,
    poly_evaluate_single,
    poly_mul_linear,
    poly_multiply,
    poly_scalar_mul,
)


class TestPolynomialOps:
    """Test cases for polynomial operations."""

    PRIME = 17  # Small prime for testing
    PARAMS_512 = RingProofParams(domain_size=512, max_ring_size=1)
    PARAMS_2048 = RingProofParams(domain_size=2048, max_ring_size=1)
    RING_PRIME = PARAMS_512.prime
    DOMAIN_512 = PARAMS_512.domain
    DOMAIN_2048 = PARAMS_2048.domain

    def test_poly_add_same_length(self):
        """Test polynomial addition with same length."""
        p1 = [1, 2, 3]
        p2 = [4, 5, 6]
        result = poly_add(p1, p2, 17)
        assert result == [5, 7, 9]

    def test_poly_add_different_length(self):
        """Test polynomial addition with different lengths."""
        p1 = [1, 2]
        p2 = [3, 4, 5, 6]
        result = poly_add(p1, p2, 17)
        assert result == [4, 6, 5, 6]

    def test_poly_add_with_modulo(self):
        """Test polynomial addition with modular reduction."""
        p1 = [10, 15]
        p2 = [8, 5]
        result = poly_add(p1, p2, 17)
        assert result == [1, 3]  # (18 mod 17, 20 mod 17)

    def test_poly_multiply_small(self):
        """Test polynomial multiplication with small polynomials."""
        p1 = [1, 2]  # 1 + 2x
        p2 = [3, 4]  # 3 + 4x
        # (1 + 2x)(3 + 4x) = 3 + 4x + 6x + 8x^2 = 3 + 10x + 8x^2
        result = poly_multiply(p1, p2, 17)
        assert result == [3, 10, 8]

    def test_poly_multiply_larger_fft(self):
        """Test polynomial multiplication using FFT path (larger polynomials)."""
        # Create polynomials large enough to trigger FFT
        p1 = list(range(1, 65))  # 64 coefficients
        p2 = list(range(1, 65))

        result = poly_multiply(p1, p2, self.RING_PRIME)

        # Result should have len(p1) + len(p2) - 1 = 127 coefficients
        assert len(result) == 127

    def test_poly_multiply_single_coefficient(self):
        """Test multiplying single-coefficient polynomials."""
        p1 = [5]
        p2 = [3]
        result = poly_multiply(p1, p2, 17)
        assert result == [15]

    def test_poly_scalar_basic(self):
        """Test polynomial scalar multiplication."""
        poly = [1, 2, 3]
        result = poly_scalar_mul(poly, 5, 17)
        assert result == [5, 10, 15]

    def test_poly_scalar_with_modulo(self):
        """Test polynomial scalar multiplication with modular reduction."""
        poly = [3, 4, 5]
        result = poly_scalar_mul(poly, 6, 17)
        # [3*6, 4*6, 5*6] = [18, 24, 30] mod 17 = [1, 7, 13]
        assert result == [1, 7, 13]

    def test_poly_evaluate_single_constant(self):
        """Test evaluating constant polynomial."""
        poly = [7]
        result = poly_evaluate_single(poly, 5, 17)
        assert result == 7

    def test_poly_evaluate_single_linear(self):
        """Test evaluating linear polynomial."""
        poly = [3, 2]  # 3 + 2x
        result = poly_evaluate_single(poly, 5, 17)
        # 3 + 2*5 = 13
        assert result == 13

    def test_poly_evaluate_single_quadratic(self):
        """Test evaluating quadratic polynomial."""
        poly = [1, 2, 3]  # 1 + 2x + 3x^2
        result = poly_evaluate_single(poly, 2, 17)
        # 1 + 2*2 + 3*4 = 1 + 4 + 12 = 17 mod 17 = 0
        assert result == 0

    def test_poly_divide_by_vanishing_quotient_zero(self):
        """Test division when deg(f) < domain_size (quotient is 0)."""
        coeffs = [1, 2, 3]  # degree 2
        domain_size = 8
        result = poly_divide_by_vanishing(coeffs, domain_size)
        assert result == [0]

    def test_poly_divide_by_vanishing_basic(self):
        """Test basic polynomial division by vanishing polynomial."""
        # f(x) = x^4 + 2x^3 + 3x^2 + 4x + 5
        coeffs = [5, 4, 3, 2, 1]  # degree 4
        domain_size = 4
        # Dividing by x^4 - 1
        # quotient is coefficient of x^4, which is 1
        result = poly_divide_by_vanishing(coeffs, domain_size)
        assert result == [1]

    def test_poly_divide_by_vanishing_larger(self):
        """Test polynomial division with larger polynomial."""
        # f(x) with degree 7, domain_size 4
        coeffs = [1, 2, 3, 4, 5, 6, 7, 8]  # coeffs[4:] = [5,6,7,8] is initial quotient
        domain_size = 4
        result = poly_divide_by_vanishing(coeffs, domain_size)
        # quotient = coeffs[n:] = [5, 6, 7, 8]
        assert len(result) == 4

    def test_poly_divide_by_vanishing_strips_zeros(self):
        """Test that division strips trailing zeros from quotient."""
        coeffs = [1, 2, 3, 4, 5, 0, 0, 0]  # trailing zeros in quotient part
        domain_size = 4
        result = poly_divide_by_vanishing(coeffs, domain_size)
        # quotient should have trailing zeros stripped
        assert result[-1] != 0 or result == [0]

    def test_poly_mul_linear_basic(self):
        """Test multiplying polynomial by linear factor."""
        poly = [1, 2]  # 1 + 2x
        # Multiply by (3x + 5) = (ax + b) with a=3, b=5
        result = poly_mul_linear(poly, 3, 5, 17)
        # (1 + 2x)(3x + 5) = 5 + 3x + 10x + 6x^2 = 5 + 13x + 6x^2
        assert result == [5, 13, 6]

    def test_poly_mul_linear_with_modulo(self):
        """Test linear multiplication with modular reduction."""
        poly = [10, 15]
        result = poly_mul_linear(poly, 2, 3, 17)
        # (10 + 15x)(2x + 3)
        # = 30 + 20x + 45x + 30x^2
        # = 30 + 65x + 30x^2
        # mod 17: [30 mod 17, 65 mod 17, 30 mod 17] = [13, 14, 13]
        assert result == [13, 14, 13]

    def test_lagrange_basis_polynomial_basic(self):
        """Test Lagrange basis polynomial computation."""
        x_coords = [0, 1, 2]
        # L_0(x) at points [0, 1, 2]
        # L_0(x) = (x-1)(x-2) / (0-1)(0-2) = (x-1)(x-2) / 2
        basis = lagrange_basis_polynomial(x_coords, 0, 17)

        # Verify L_0(0) = 1
        val_at_0 = poly_evaluate_single(basis, 0, 17)
        assert val_at_0 == 1

        # Verify L_0(1) = 0
        val_at_1 = poly_evaluate_single(basis, 1, 17)
        assert val_at_1 == 0

        # Verify L_0(2) = 0
        val_at_2 = poly_evaluate_single(basis, 2, 17)
        assert val_at_2 == 0

    def test_lagrange_basis_polynomial_d512(self):
        """Test Lagrange basis polynomial for roots of unity domain DOMAIN_512."""
        # Should use optimized path for DOMAIN_512
        basis = lagrange_basis_polynomial(self.DOMAIN_512, 0, self.RING_PRIME)
        assert len(basis) == 512

    def test_lagrange_basis_polynomial_d2048(self):
        """Test Lagrange basis polynomial for roots of unity domain DOMAIN_2048."""
        # Should use optimized path for DOMAIN_2048
        basis = lagrange_basis_polynomial(self.DOMAIN_2048, 0, self.RING_PRIME)
        assert len(basis) == 2048

    def test_lagrange_basis_polynomial_generic_root_domain(self):
        """Test optimized Lagrange basis on generated roots-of-unity domains."""
        omega = get_root_of_unity(8, self.RING_PRIME)
        domain = [pow(omega, i, self.RING_PRIME) for i in range(8)]
        basis = lagrange_basis_polynomial(domain, 3, self.RING_PRIME)

        for index, point in enumerate(domain):
            expected = 1 if index == 3 else 0
            assert poly_evaluate_single(basis, point, self.RING_PRIME) == expected

    def test_get_root_of_unity_caching(self):
        """Test that root of unity computation is cached."""
        # First call
        root1 = get_root_of_unity(8, self.RING_PRIME)
        # Second call should be cached
        root2 = get_root_of_unity(8, self.RING_PRIME)

        assert root1 == root2
        # Verify it's actually a root of unity
        assert pow(root1, 8, self.RING_PRIME) == 1

    def test_get_root_of_unity_various_sizes(self):
        """Test root of unity for various sizes."""
        for n in [4, 8, 16, 32, 64]:
            root = get_root_of_unity(n, self.RING_PRIME)
            assert pow(root, n, self.RING_PRIME) == 1
            # Should be primitive (root^(n/2) != 1)
            if n > 1:
                assert pow(root, n // 2, self.RING_PRIME) != 1


class TestPolynomialOpsEdgeCases:
    """Edge case tests for polynomial operations."""

    def test_poly_add_empty(self):
        """Test adding empty polynomials."""
        result = poly_add([], [], 17)
        assert result == []

    def test_poly_multiply_by_zero(self):
        """Test multiplying by zero polynomial."""
        p1 = [1, 2, 3]
        p2 = [0]
        result = poly_multiply(p1, p2, 17)
        assert result == [0, 0, 0]

    def test_poly_scalar_zero(self):
        """Test scalar multiplication by zero."""
        poly = [1, 2, 3]
        result = poly_scalar_mul(poly, 0, 17)
        assert result == [0, 0, 0]

    def test_poly_evaluate_empty(self):
        """Test evaluating empty polynomial."""
        result = poly_evaluate_single([], 5, 17)
        assert result == 0
