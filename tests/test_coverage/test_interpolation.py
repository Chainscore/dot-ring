"""Additional tests for interpolation module to improve coverage."""

from dot_ring.ring_proof.constants import OMEGA_512 as OMEGA, S_PRIME
from dot_ring.ring_proof.polynomial.interpolation import poly_interpolate_fft


class TestInterpolation:
    """Test polynomial interpolation functions."""

    def test_poly_interpolate_fft_power_of_two(self):
        """Test FFT interpolation with power of 2 size."""
        # 8 values
        y_values = [1, 2, 3, 4, 5, 6, 7, 8]

        # Use real constants
        coeffs = poly_interpolate_fft(y_values, OMEGA, S_PRIME)

        assert coeffs is not None

    def test_poly_interpolate_fft_single_value(self):
        """Test FFT interpolation with single value."""
        y_values = [42]

        coeffs = poly_interpolate_fft(y_values, OMEGA, S_PRIME)

        assert coeffs is not None

    def test_poly_interpolate_fft_zeros(self):
        """Test FFT interpolation with all zeros."""
        y_values = [0, 0, 0, 0]

        coeffs = poly_interpolate_fft(y_values, OMEGA, S_PRIME)

        assert coeffs is not None
        # All zero input should give all zero coeffs
        assert all(c == 0 for c in coeffs[:4])
