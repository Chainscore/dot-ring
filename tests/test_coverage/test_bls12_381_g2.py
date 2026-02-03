"""Additional tests for BLS12-381 G2 module."""

from dot_ring.curve.specs.bls12_381_G2 import (
    BLS12_381_G2_RO,
    BLS12_381_G2Curve,
    BLS12_381_G2Params,
)


class TestBLS12381G2Curve:
    """Test BLS12-381 G2 curve operations."""

    def test_curve_parameters(self):
        """Test curve parameters are set."""
        curve = BLS12_381_G2Curve()

        assert curve.PRIME_FIELD is not None
        assert curve.ORDER is not None
        assert curve.COFACTOR is not None

    def test_curve_generator(self):
        """Test generator point."""
        curve = BLS12_381_G2Curve()

        assert curve.GENERATOR_X is not None
        assert curve.GENERATOR_Y is not None


class TestBLS12381G2Params:
    """Test BLS12-381 G2 parameters."""

    def test_params_prime(self):
        """Test params prime field."""
        assert BLS12_381_G2Params.PRIME_FIELD is not None

    def test_params_order(self):
        """Test params order."""
        assert BLS12_381_G2Params.ORDER is not None

    def test_params_cofactor(self):
        """Test params cofactor."""
        assert BLS12_381_G2Params.COFACTOR is not None

    def test_params_weierstrass_a(self):
        """Test Weierstrass A parameter."""
        assert BLS12_381_G2Params.WEIERSTRASS_A is not None

    def test_params_weierstrass_b(self):
        """Test Weierstrass B parameter."""
        assert BLS12_381_G2Params.WEIERSTRASS_B is not None


class TestBLS12381G2RO:
    """Test BLS12-381 G2 Random Oracle suite."""

    def test_curve_reference(self):
        """Test curve reference."""
        assert BLS12_381_G2_RO.curve is not None
