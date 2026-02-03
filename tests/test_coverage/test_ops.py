"""Tests for polynomial operations module to improve coverage."""

import pytest

from dot_ring.ring_proof.constants import D_512, D_2048, S_PRIME
from dot_ring.ring_proof.polynomial.ops import (
    get_root_of_unity,
    lagrange_basis_polynomial,
    mod_inverse,
    poly_add,
    poly_division_general,
    poly_evaluate,
    poly_evaluate_single,
    poly_mul_linear,
    poly_multiply,
    poly_scalar,
    poly_subtract,
    vect_scalar_mul,
)


class TestPolynomialOps:
    """Test cases for polynomial operations."""

    PRIME = 17  # Small prime for testing

    def test_mod_inverse_basic(self):
        """Test modular inverse computation."""
        # 3 * 6 = 18 = 1 mod 17, so inv(3) = 6 mod 17
        result = mod_inverse(3, 17)
        assert (3 * result) % 17 == 1

    def test_mod_inverse_raises_for_no_inverse(self):
        """Test mod_inverse raises ValueError when no inverse exists."""
        # 0 has no inverse
        with pytest.raises(ValueError, match="No inverse exists"):
            mod_inverse(0, 17)

    def test_mod_inverse_various_values(self):
        """Test mod_inverse for various values."""
        for val in [1, 2, 5, 7, 11, 13]:
            inv = mod_inverse(val, 17)
            assert (val * inv) % 17 == 1

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

    def test_poly_subtract_same_length(self):
        """Test polynomial subtraction with same length."""
        p1 = [5, 7, 9]
        p2 = [1, 2, 3]
        result = poly_subtract(p1, p2, 17)
        assert result == [4, 5, 6]

    def test_poly_subtract_different_length(self):
        """Test polynomial subtraction with different lengths."""
        p1 = [5, 7]
        p2 = [1, 2, 3, 4]
        result = poly_subtract(p1, p2, 17)
        # [5-1, 7-2, 0-3, 0-4] = [4, 5, -3, -4] mod 17 = [4, 5, 14, 13]
        assert result == [4, 5, 14, 13]

    def test_poly_subtract_with_negative_result(self):
        """Test polynomial subtraction resulting in negative (modular)."""
        p1 = [1, 2]
        p2 = [5, 8]
        result = poly_subtract(p1, p2, 17)
        # [1-5, 2-8] = [-4, -6] mod 17 = [13, 11]
        assert result == [13, 11]

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

        result = poly_multiply(p1, p2, S_PRIME)

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
        result = poly_scalar(poly, 5, 17)
        assert result == [5, 10, 15]

    def test_poly_scalar_with_modulo(self):
        """Test polynomial scalar multiplication with modular reduction."""
        poly = [3, 4, 5]
        result = poly_scalar(poly, 6, 17)
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

    def test_poly_evaluate_single_point_integer(self):
        """Test poly_evaluate with single integer point."""
        poly = [1, 2, 3]
        result = poly_evaluate(poly, 5, 17)
        # Returns single value for single point
        expected = poly_evaluate_single(poly, 5, 17)
        assert result == expected

    def test_poly_evaluate_multiple_points(self):
        """Test poly_evaluate with multiple arbitrary points."""
        poly = [1, 2]  # 1 + 2x
        points = [0, 1, 2, 3]
        result = poly_evaluate(poly, points, 17)
        # At x=0: 1, x=1: 3, x=2: 5, x=3: 7
        assert result == [1, 3, 5, 7]

    def test_poly_evaluate_d512_domain(self):
        """Test poly_evaluate with D_512 domain uses FFT."""
        poly = [1, 2, 3, 4]
        result = poly_evaluate(poly, D_512, S_PRIME)
        assert len(result) == 512

    def test_poly_evaluate_d2048_domain(self):
        """Test poly_evaluate with D_2048 domain uses FFT."""
        poly = [1, 2, 3, 4]
        result = poly_evaluate(poly, D_2048, S_PRIME)
        assert len(result) == 2048

    def test_poly_division_general_quotient_zero(self):
        """Test division when deg(f) < domain_size (quotient is 0)."""
        coeffs = [1, 2, 3]  # degree 2
        domain_size = 8
        result = poly_division_general(coeffs, domain_size)
        assert result == [0]

    def test_poly_division_general_basic(self):
        """Test basic polynomial division by vanishing polynomial."""
        # f(x) = x^4 + 2x^3 + 3x^2 + 4x + 5
        coeffs = [5, 4, 3, 2, 1]  # degree 4
        domain_size = 4
        # Dividing by x^4 - 1
        # quotient is coefficient of x^4, which is 1
        result = poly_division_general(coeffs, domain_size)
        assert result == [1]

    def test_poly_division_general_larger(self):
        """Test polynomial division with larger polynomial."""
        # f(x) with degree 7, domain_size 4
        coeffs = [1, 2, 3, 4, 5, 6, 7, 8]  # coeffs[4:] = [5,6,7,8] is initial quotient
        domain_size = 4
        result = poly_division_general(coeffs, domain_size)
        # quotient = coeffs[n:] = [5, 6, 7, 8]
        assert len(result) == 4

    def test_poly_division_general_strips_zeros(self):
        """Test that division strips trailing zeros from quotient."""
        coeffs = [1, 2, 3, 4, 5, 0, 0, 0]  # trailing zeros in quotient part
        domain_size = 4
        result = poly_division_general(coeffs, domain_size)
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
        """Test Lagrange basis polynomial for roots of unity domain D_512."""
        # Should use optimized path for D_512
        basis = lagrange_basis_polynomial(D_512, 0, S_PRIME)
        assert len(basis) == 512

    def test_lagrange_basis_polynomial_d2048(self):
        """Test Lagrange basis polynomial for roots of unity domain D_2048."""
        # Should use optimized path for D_2048
        basis = lagrange_basis_polynomial(D_2048, 0, S_PRIME)
        assert len(basis) == 2048

    def test_get_root_of_unity_caching(self):
        """Test that root of unity computation is cached."""
        # First call
        root1 = get_root_of_unity(8, S_PRIME)
        # Second call should be cached
        root2 = get_root_of_unity(8, S_PRIME)

        assert root1 == root2
        # Verify it's actually a root of unity
        assert pow(root1, 8, S_PRIME) == 1

    def test_get_root_of_unity_various_sizes(self):
        """Test root of unity for various sizes."""
        for n in [4, 8, 16, 32, 64]:
            root = get_root_of_unity(n, S_PRIME)
            assert pow(root, n, S_PRIME) == 1
            # Should be primitive (root^(n/2) != 1)
            if n > 1:
                assert pow(root, n // 2, S_PRIME) != 1

    def test_vect_scalar_mul_basic(self):
        """Test vector scalar multiplication."""
        vec = [1, 2, 3, 4]
        result = vect_scalar_mul(vec, 5, 17)
        assert result == [5, 10, 15, 3]  # 20 mod 17 = 3

    def test_vect_scalar_mul_no_modulo(self):
        """Test vector scalar multiplication without modulo."""
        vec = [1, 2, 3]
        result = vect_scalar_mul(vec, 5, None)
        assert result == [5, 10, 15]


class TestPolynomialOpsEdgeCases:
    """Edge case tests for polynomial operations."""

    def test_poly_add_empty(self):
        """Test adding empty polynomials."""
        result = poly_add([], [], 17)
        assert result == []

    def test_poly_subtract_empty(self):
        """Test subtracting empty polynomials."""
        result = poly_subtract([], [], 17)
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
        result = poly_scalar(poly, 0, 17)
        assert result == [0, 0, 0]

    def test_poly_evaluate_empty(self):
        """Test evaluating empty polynomial."""
        result = poly_evaluate_single([], 5, 17)
        assert result == 0
