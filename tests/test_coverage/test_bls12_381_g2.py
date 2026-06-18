"""Additional tests for BLS12-381 G2 module."""

from dot_ring.curve.specs.bls12_381_G2 import (
    BLS12_381_G2_PARAMS,
    BLS12_381_G2_RO,
)


class TestBLS12381G2Curve:
    """Test BLS12-381 G2 curve operations."""

    def test_curve_parameters(self):
        """Test curve parameters are set."""
        curve = BLS12_381_G2_RO.curve

        assert curve.params.field_modulus is not None
        assert curve.params.subgroup_order is not None
        assert curve.params.cofactor is not None

    def test_curve_generator(self):
        """Test generator point."""
        curve = BLS12_381_G2_RO.curve

        assert curve.params.generator[0] is not None
        assert curve.params.generator[1] is not None


class TestBLS12381G2Params:
    """Test BLS12-381 G2 parameters."""

    def test_params_prime(self):
        """Test params prime field."""
        assert BLS12_381_G2_PARAMS.field_modulus is not None

    def test_params_order(self):
        """Test params order."""
        assert BLS12_381_G2_PARAMS.subgroup_order is not None

    def test_params_cofactor(self):
        """Test params cofactor."""
        assert BLS12_381_G2_PARAMS.cofactor is not None

    def test_params_weierstrass_a(self):
        """Test Weierstrass A parameter."""
        assert BLS12_381_G2_PARAMS.a is not None

    def test_params_weierstrass_b(self):
        """Test Weierstrass B parameter."""
        assert BLS12_381_G2_PARAMS.b is not None


class TestBLS12381G2RO:
    """Test BLS12-381 G2 Random Oracle suite."""

    def test_curve_reference(self):
        """Test curve reference."""
        assert BLS12_381_G2_RO.curve is not None
