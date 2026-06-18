"""Additional tests for curve.py module to improve coverage."""

from dot_ring.curve.specs.bandersnatch import Bandersnatch_TE_Curve
from dot_ring.curve.specs.ed25519 import Ed25519_RO


class TestCurveVariant:
    """Test CurveVariant class."""

    def test_variant_has_curve(self):
        """Test variant has curve reference."""
        assert Ed25519_RO.curve is not None

    def test_bandersnatch_te_curve_params(self):
        """Test Bandersnatch TE curve parameters."""
        curve = Bandersnatch_TE_Curve

        assert curve.params.field_modulus is not None
        assert curve.params.subgroup_order is not None


class TestEdwardsCurve:
    """Test Edwards curve base class."""

    def test_ed25519_curve_params(self):
        """Test Ed25519 curve parameters."""
        curve = Ed25519_RO.curve

        assert curve.params.field_modulus is not None
        assert curve.params.subgroup_order is not None
        assert curve.params.generator[0] is not None
        assert curve.params.generator[1] is not None

    def test_ed25519_curve_cofactor(self):
        """Test Ed25519 cofactor."""
        curve = Ed25519_RO.curve

        assert curve.params.cofactor == 8

    def test_ed25519_curve_name(self):
        """Test Ed25519 curve has name-like attribute."""
        curve = Ed25519_RO.curve
        # Just test it doesn't crash
        str(curve)
