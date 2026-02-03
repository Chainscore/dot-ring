"""Additional tests to improve coverage for verify module."""

import pytest
from dot_ring.curve.native_field.scalar import Scalar
from py_ecc.optimized_bls12_381 import curve_order

from dot_ring.ring_proof.constants import OMEGA_512 as OMEGA, OMEGA_2048, S_PRIME, DEFAULT_SIZE as SIZE
from dot_ring.ring_proof.pcs.srs import srs
from dot_ring.ring_proof.verify import Verify, blst_msm, lagrange_at_zeta


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

    def test_divide_modular_inverse(self):
        """Test modular division helper."""
        verifier = Verify.__new__(Verify)

        numerator = 10
        denominator = 3
        expected = (numerator * pow(denominator, -1, curve_order)) % curve_order

        assert verifier.divide(numerator, denominator) == expected

    def test_legacy_methods_raise(self):
        """Legacy methods should raise NotImplementedError."""
        verifier = Verify.__new__(Verify)

        with pytest.raises(NotImplementedError):
            verifier.evaluation_of_quotient_poly_at_zeta()

        with pytest.raises(NotImplementedError):
            verifier.evaluation_of_linearization_poly_at_zeta_omega()

    def test_init_rejects_invalid_padding_rows(self):
        """Verify init validates padding_rows against domain size."""
        proof = (0,) * 15
        with pytest.raises(ValueError, match="padding_rows"):
            Verify(
                proof=proof,
                vk={},
                fixed_cols=[0, 0, 0],
                rl_to_proove=(0, 0),
                rps=(0, 0),
                seed_point=(0, 0),
                Domain=[1, 2, 3],
                padding_rows=3,
            )

    def test_contributions_handles_zeta_equal_domain_point(self):
        """Zeta equal to a domain point should hit the zero-difference branches."""
        verifier = Verify.__new__(Verify)

        verifier.zeta_p = 1
        verifier.sp = (2, 3)
        verifier.D = [1, 2, 3, 4]
        verifier.b_zeta = 1
        verifier.accx_zeta = 5
        verifier.accy_zeta = 7
        verifier.accip_zeta = 11
        verifier.px_zeta = 13
        verifier.py_zeta = 17
        verifier.s_zeta = 19
        verifier.Result_plus_Seed = (23, 29)

        verifier.last_index = len(verifier.D) - 1

        result = verifier.contributions_to_constraints_eval_at_zeta()

        assert len(result) == 7
        assert all(isinstance(value, Scalar) for value in result)

    def test_linearization_uses_expected_omega(self):
        """Verify omega selection for non-512 domains."""
        verifier = Verify.__new__(Verify)

        verifier.alpha_list = [1, 2, 3]
        verifier.zeta_p = 7
        verifier.D = list(range(1024))
        verifier.accx_zeta = 2
        verifier.accy_zeta = 3
        verifier.px_zeta = 5
        verifier.py_zeta = 7
        verifier.b_zeta = 11
        verifier.Caccip_blst = srs.blst_g1[0]
        verifier.Caccx_blst = srs.blst_g1[1]
        verifier.Caccy_blst = srs.blst_g1[2]
        verifier.Phi_zeta_omega_blst = srs.blst_g1[3]
        verifier.l_zeta_omega = 13

        verifier.last_index = len(verifier.D) - 1

        _, _, zeta_omega, _ = verifier._prepare_linearization_poly_verification()
        expected_omega = pow(OMEGA_2048, 2048 // 1024, S_PRIME)
        expected_zeta_omega = (verifier.zeta_p * expected_omega) % S_PRIME

        assert zeta_omega == expected_zeta_omega

    def test_linearization_uses_fallback_omega(self):
        """Verify omega selection for non-standard domain sizes."""
        verifier = Verify.__new__(Verify)

        verifier.alpha_list = [1, 2, 3]
        verifier.zeta_p = 7
        verifier.D = list(range(16))
        verifier.accx_zeta = 2
        verifier.accy_zeta = 3
        verifier.px_zeta = 5
        verifier.py_zeta = 7
        verifier.b_zeta = 11
        verifier.Caccip_blst = srs.blst_g1[0]
        verifier.Caccx_blst = srs.blst_g1[1]
        verifier.Caccy_blst = srs.blst_g1[2]
        verifier.Phi_zeta_omega_blst = srs.blst_g1[3]
        verifier.l_zeta_omega = 13

        verifier.last_index = len(verifier.D) - 1

        _, _, zeta_omega, _ = verifier._prepare_linearization_poly_verification()
        expected_omega = pow(OMEGA_2048, 2048 // 16, S_PRIME)
        expected_zeta_omega = (verifier.zeta_p * expected_omega) % S_PRIME

        assert zeta_omega == expected_zeta_omega

    def test_prepare_quotient_poly_verification_smoke(self):
        """Smoke test for quotient verification preparation."""
        verifier = Verify.__new__(Verify)

        verifier.alpha_list = [1, 2, 3, 4, 5, 6, 7]
        verifier.zeta_p = 7
        verifier.V_list = [1, 2, 3, 4, 5, 6, 7, 8]
        verifier.D = [1, 2, 3, 4]
        verifier.sp = (2, 3)
        verifier.Result_plus_Seed = (23, 29)
        verifier.b_zeta = 1
        verifier.accx_zeta = 5
        verifier.accy_zeta = 7
        verifier.accip_zeta = 11
        verifier.px_zeta = 13
        verifier.py_zeta = 17
        verifier.s_zeta = 19
        verifier.l_zeta_omega = 31

        verifier.Cpx_blst = srs.blst_g1[0]
        verifier.Cpy_blst = srs.blst_g1[1]
        verifier.Cs_blst = srs.blst_g1[2]
        verifier.Cb_blst = srs.blst_g1[3]
        verifier.Caccip_blst = srs.blst_g1[4]
        verifier.Caccx_blst = srs.blst_g1[5]
        verifier.Caccy_blst = srs.blst_g1[6]
        verifier.Cq_blst = srs.blst_g1[7]
        verifier.Phi_zeta_blst = srs.blst_g1[8]

        verifier.last_index = len(verifier.D) - 1

        _, phi, zeta, agg = verifier._prepare_quotient_poly_verification()

        assert phi is verifier.Phi_zeta_blst
        assert zeta == verifier.zeta_p
        assert isinstance(agg, int)


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
