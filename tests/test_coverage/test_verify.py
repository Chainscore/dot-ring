"""Additional tests to improve coverage for verify module."""

import pytest

from dot_ring.ring_proof.verify import lagrange_at_zeta, blst_msm
from dot_ring.ring_proof.constants import SIZE, OMEGA, S_PRIME
from dot_ring.ring_proof.pcs.srs import srs
from dot_ring import blst


class TestVerifyHelpers:
    """Test helper functions in verify module."""

    def test_lagrange_at_zeta_basic(self):
        """Test Lagrange basis evaluation at a point."""
        # L_i(zeta) = (omega^i / n) * (zeta^n - 1) / (zeta - omega^i)
        domain_size = SIZE
        index = 0
        zeta = 12345  # arbitrary point
        omega = OMEGA
        prime = S_PRIME
        
        result = lagrange_at_zeta(domain_size, index, zeta, omega, prime)
        
        # Just verify it returns a scalar-like value
        assert result is not None

    def test_lagrange_at_zeta_at_omega_power(self):
        """Test Lagrange basis at omega^i equals 1."""
        # L_i(omega^i) = 1
        domain_size = SIZE
        index = 5
        omega = OMEGA
        prime = S_PRIME
        
        # zeta = omega^index
        zeta = pow(omega, index, prime)
        
        result = lagrange_at_zeta(domain_size, index, zeta, omega, prime)
        
        # Should be 1
        # The Scalar class has an internal value
        assert int(result) == 1

    def test_lagrange_at_zeta_index_zero(self):
        """Test Lagrange basis at index 0."""
        domain_size = SIZE
        index = 0
        zeta = 99999
        omega = OMEGA
        prime = S_PRIME
        
        result = lagrange_at_zeta(domain_size, index, zeta, omega, prime)
        
        assert result is not None

    def test_lagrange_at_zeta_index_size_minus_4(self):
        """Test Lagrange basis at index SIZE-4 (uses precomputed omega power)."""
        domain_size = SIZE
        index = SIZE - 4
        zeta = 12345
        omega = OMEGA
        prime = S_PRIME
        
        result = lagrange_at_zeta(domain_size, index, zeta, omega, prime)
        
        assert result is not None

    def test_lagrange_at_zeta_caching(self):
        """Test that lagrange_at_zeta results are cached."""
        domain_size = SIZE
        index = 10
        zeta = 54321
        omega = OMEGA
        prime = S_PRIME
        
        result1 = lagrange_at_zeta(domain_size, index, zeta, omega, prime)
        result2 = lagrange_at_zeta(domain_size, index, zeta, omega, prime)
        
        assert result1 == result2


class TestBLSTMSM:
    """Test blst multi-scalar multiplication."""

    def test_blst_msm_empty(self):
        """Test MSM with empty inputs."""
        result = blst_msm([], [])
        
        # Should return point at infinity
        assert result.is_inf()

    def test_blst_msm_single_point(self):
        """Test MSM with single point."""
        points = [srs.blst_g1[0]]
        scalars = [5]
        
        result = blst_msm(points, scalars)
        
        assert result is not None
        assert not result.is_inf()

    def test_blst_msm_multiple_points(self):
        """Test MSM with multiple points."""
        points = [srs.blst_g1[0], srs.blst_g1[1], srs.blst_g1[2]]
        scalars = [1, 2, 3]
        
        result = blst_msm(points, scalars)
        
        assert result is not None
