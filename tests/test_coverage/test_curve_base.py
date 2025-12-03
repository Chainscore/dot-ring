"""Additional tests for curve.py module to improve coverage."""

import pytest

from dot_ring.curve.curve import CurveVariant
from dot_ring.curve.specs.ed25519 import Ed25519_RO, Ed25519Curve
from dot_ring.curve.specs.bandersnatch import Bandersnatch_TE_Curve


class TestCurveVariant:
    """Test CurveVariant class."""

    def test_variant_has_curve(self):
        """Test variant has curve reference."""
        assert Ed25519_RO.curve is not None

    def test_bandersnatch_te_curve_params(self):
        """Test Bandersnatch TE curve parameters."""
        curve = Bandersnatch_TE_Curve
        
        assert curve.PRIME_FIELD is not None
        assert curve.ORDER is not None


class TestEdwardsCurve:
    """Test Edwards curve base class."""

    def test_ed25519_curve_params(self):
        """Test Ed25519 curve parameters."""
        curve = Ed25519Curve()
        
        assert curve.PRIME_FIELD is not None
        assert curve.ORDER is not None
        assert curve.GENERATOR_X is not None
        assert curve.GENERATOR_Y is not None

    def test_ed25519_curve_cofactor(self):
        """Test Ed25519 cofactor."""
        curve = Ed25519Curve()
        
        assert curve.COFACTOR == 8

    def test_ed25519_curve_name(self):
        """Test Ed25519 curve has name-like attribute."""
        curve = Ed25519Curve()
        # Just test it doesn't crash
        str(curve)
