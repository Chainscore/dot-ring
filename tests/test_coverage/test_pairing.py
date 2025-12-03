"""Tests for pairing module to improve coverage."""

import pytest

from dot_ring import blst
from dot_ring.ring_proof.pcs.pairing import (
    _ensure_blst_p1_affine,
    _ensure_blst_p2_affine,
    blst_miller_loop,
    blst_final_verify,
)
from dot_ring.ring_proof.pcs.srs import srs


class TestPairingHelpers:
    """Test pairing helper functions."""

    def test_ensure_p1_affine_from_p1(self):
        """Test converting P1 to P1_Affine."""
        # Get a P1_Affine and convert to P1
        p1_affine = srs.blst_g1[0]
        # Create P1 from bytes (serialize then deserialize as P1)
        p1_bytes = p1_affine.serialize()
        p1_proj = blst.P1(p1_bytes)
        
        result = _ensure_blst_p1_affine(p1_proj)
        
        assert isinstance(result, blst.P1_Affine)

    def test_ensure_p1_affine_from_p1_affine(self):
        """Test that P1_Affine is converted (not returned as-is since SRS stores P1)."""
        # The SRS actually stores P1 objects, not P1_Affine
        p1 = srs.blst_g1[0]
        
        result = _ensure_blst_p1_affine(p1)
        
        # Should return a P1_Affine
        assert isinstance(result, blst.P1_Affine)

    def test_ensure_p1_affine_invalid_type(self):
        """Test that invalid type raises TypeError."""
        with pytest.raises(TypeError, match="Unsupported G1 point type"):
            _ensure_blst_p1_affine("not a point")  # type: ignore

    def test_ensure_p2_affine_from_p2(self):
        """Test converting P2 to P2_Affine."""
        # Get a P2_Affine and convert to P2
        p2_affine = srs.blst_g2[0]
        # Create P2 from bytes
        p2_bytes = p2_affine.serialize()
        p2_proj = blst.P2(p2_bytes)
        
        result = _ensure_blst_p2_affine(p2_proj)
        
        assert isinstance(result, blst.P2_Affine)

    def test_ensure_p2_affine_from_p2_affine(self):
        """Test that P2_Affine is converted."""
        # The SRS stores P2 objects
        p2 = srs.blst_g2[0]
        
        result = _ensure_blst_p2_affine(p2)
        
        # Should return a P2_Affine
        assert isinstance(result, blst.P2_Affine)

    def test_ensure_p2_affine_invalid_type(self):
        """Test that invalid type raises TypeError."""
        with pytest.raises(TypeError, match="Unsupported G2 point type"):
            _ensure_blst_p2_affine("not a point")  # type: ignore


class TestMillerLoop:
    """Test Miller loop computation."""

    def test_miller_loop_affine_points(self):
        """Test Miller loop with affine points."""
        p1 = srs.blst_g1[0]
        p2 = srs.blst_g2[0]
        
        result = blst_miller_loop(p1, p2)
        
        assert isinstance(result, blst.PT)

    def test_miller_loop_projective_points(self):
        """Test Miller loop with projective points."""
        p1 = srs.blst_g1[0]
        p2 = srs.blst_g2[0]
        
        # Create projective points from bytes
        p1_bytes = p1.serialize() if hasattr(p1, 'serialize') else p1.to_affine().serialize()
        p2_bytes = p2.serialize() if hasattr(p2, 'serialize') else p2.to_affine().serialize()
        
        p1_proj = blst.P1(p1_bytes)
        p2_proj = blst.P2(p2_bytes)
        
        result = blst_miller_loop(p1_proj, p2_proj)
        
        assert isinstance(result, blst.PT)


class TestFinalVerify:
    """Test final pairing verification."""

    def test_final_verify_equal_pairings(self):
        """Test final verify with equal pairings returns True."""
        p1 = srs.blst_g1[0]
        p2 = srs.blst_g2[0]
        
        pt1 = blst_miller_loop(p1, p2)
        pt2 = blst_miller_loop(p1, p2)
        
        result = blst_final_verify(pt1, pt2)
        
        assert result is True

    def test_final_verify_different_pairings(self):
        """Test final verify with different pairings returns False."""
        p1_1 = srs.blst_g1[0]
        p1_2 = srs.blst_g1[1]  # Different G1 point
        p2 = srs.blst_g2[0]
        
        pt1 = blst_miller_loop(p1_1, p2)
        pt2 = blst_miller_loop(p1_2, p2)
        
        result = blst_final_verify(pt1, pt2)
        
        assert result is False
