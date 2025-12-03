"""Tests for SW curve module to improve coverage using existing curve specs."""

import pytest

from dot_ring.curve.specs.secp256k1 import Secp256k1Curve, Secp256k1Params, Secp256k1_SW_Curve
from dot_ring.curve.specs.p256 import P256Curve, P256Params
from dot_ring.curve.specs.p384 import P384Curve, P384Params
from dot_ring.curve.specs.p521 import P521Curve, P521Params
from dot_ring.curve.specs.bls12_381_G1 import BLS12_381_G1Curve, BLS12_381_G1Params


class TestSWCurveIsOnCurve:
    """Test is_on_curve method for SW curves."""

    def test_secp256k1_generator_on_curve(self):
        """Test that secp256k1 generator is on curve."""
        curve = Secp256k1_SW_Curve
        point = (curve.GENERATOR_X, curve.GENERATOR_Y)
        assert curve.is_on_curve(point) is True

    def test_secp256k1_invalid_point(self):
        """Test invalid point detection on secp256k1."""
        curve = Secp256k1_SW_Curve
        # Arbitrary point likely not on curve
        point = (12345, 67890)
        assert curve.is_on_curve(point) is False

    def test_p256_generator_on_curve(self):
        """Test that P256 generator is on curve."""
        curve = P256Curve()
        point = (curve.GENERATOR_X, curve.GENERATOR_Y)
        assert curve.is_on_curve(point) is True

    def test_p384_generator_on_curve(self):
        """Test that P384 generator is on curve."""
        curve = P384Curve()
        point = (curve.GENERATOR_X, curve.GENERATOR_Y)
        assert curve.is_on_curve(point) is True

    def test_p521_generator_on_curve(self):
        """Test that P521 generator is on curve."""
        curve = P521Curve()
        point = (curve.GENERATOR_X, curve.GENERATOR_Y)
        assert curve.is_on_curve(point) is True


class TestSWCurveJInvariant:
    """Test j-invariant calculation."""

    def test_secp256k1_j_invariant(self):
        """Test j-invariant calculation for secp256k1."""
        curve = Secp256k1_SW_Curve
        j = curve.j_invariant()
        # For secp256k1 with a=0, j-invariant should be 0
        assert j == 0

    def test_p256_j_invariant(self):
        """Test j-invariant calculation for P256."""
        curve = P256Curve()
        j = curve.j_invariant()
        # j-invariant is non-zero for P256
        assert isinstance(j, int)


class TestSWCurveValidation:
    """Test SW curve parameter validation."""

    def test_secp256k1_valid(self):
        """Test that secp256k1 passes validation."""
        curve = Secp256k1_SW_Curve
        assert curve._validate_weierstrass_params() is True

    def test_p256_valid(self):
        """Test that P256 passes validation."""
        curve = P256Curve()
        assert curve._validate_weierstrass_params() is True


class TestBLS12381G1:
    """Test BLS12-381 G1 curve operations."""

    def test_generator_on_curve(self):
        """Test that BLS12-381 G1 generator is on curve."""
        curve = BLS12_381_G1Curve()
        point = (curve.GENERATOR_X, curve.GENERATOR_Y)
        assert curve.is_on_curve(point) is True

    def test_j_invariant(self):
        """Test j-invariant for BLS12-381 G1."""
        curve = BLS12_381_G1Curve()
        j = curve.j_invariant()
        # BLS12-381 has a=0, so j=0
        assert j == 0
