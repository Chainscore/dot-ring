"""Additional tests for utils module to improve coverage."""

from dot_ring.ring_proof.constants import S_PRIME
from dot_ring.ring_proof.pcs.utils import synthetic_div


class TestPCSUtils:
    """Test PCS utility functions."""

    def test_synthetic_div_basic(self):
        """Test synthetic division basic case."""
        # Polynomial coefficients (x^2 + 2x + 1)
        poly = [1, 2, 1]  # 1 + 2x + x^2
        x = 1
        y = 4  # f(1) = 1 + 2 + 1 = 4

        quotient = synthetic_div(poly, x, y)

        assert quotient is not None

    def test_synthetic_div_with_modulo(self):
        """Test synthetic division with modulo."""
        poly = [1, 2, 3, 4]
        x = 5
        # Compute y = f(x)
        y = sum(c * pow(x, i, S_PRIME) for i, c in enumerate(poly)) % S_PRIME

        quotient = synthetic_div(poly, x, y)

        assert quotient is not None

    def test_synthetic_div_simple_linear(self):
        """Test synthetic division of linear polynomial."""
        # f(x) = 2 + 3x divided by (x - 2)
        # f(2) = 2 + 6 = 8
        poly = [2, 3]  # 2 + 3x
        x = 2
        y = 8

        quotient = synthetic_div(poly, x, y)

        assert quotient is not None
        # Quotient should be just [3] since f(x) = 8 + 3(x - 2) = 8 + 3x - 6 = 2 + 3x

    def test_synthetic_div_larger_poly(self):
        """Test synthetic division with larger polynomial."""
        poly = [1, 1, 1, 1, 1]  # 1 + x + x^2 + x^3 + x^4
        x = 3
        # f(3) = 1 + 3 + 9 + 27 + 81 = 121
        y = 121

        quotient = synthetic_div(poly, x, y)

        assert quotient is not None
        assert len(quotient) == len(poly) - 1
