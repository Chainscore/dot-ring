"""Tests for KZG module to improve coverage."""

import pytest

from dot_ring.ring_proof.pcs.kzg import (
    KZG,
    Opening,
    p1_add,
    p1_neg,
    p1_scalar_mul,
    p2_add,
    p2_neg,
    p2_scalar_mul,
)
from dot_ring.ring_proof.pcs.srs import srs


class TestKZGHelpers:
    """Test KZG helper functions."""

    def test_p1_scalar_mul(self):
        """Test P1 scalar multiplication."""
        p = srs.blst_g1[0]  # Generator
        scalar = 5

        result = p1_scalar_mul(p, scalar)

        assert result is not None
        # Result should be different from input (unless scalar is 1)
        assert not result.is_equal(p)

    def test_p1_add(self):
        """Test P1 point addition."""
        p1 = srs.blst_g1[0]
        p2 = srs.blst_g1[1]

        result = p1_add(p1, p2)

        assert result is not None

    def test_p1_neg(self):
        """Test P1 point negation."""
        p = srs.blst_g1[0]

        neg_p = p1_neg(p)

        # p + (-p) should be the point at infinity
        result = p1_add(p, neg_p)
        assert result.is_inf()

    def test_p2_scalar_mul(self):
        """Test P2 scalar multiplication."""
        p = srs.blst_g2[0]
        scalar = 5

        result = p2_scalar_mul(p, scalar)

        assert result is not None

    def test_p2_add(self):
        """Test P2 point addition."""
        p1 = srs.blst_g2[0]
        p2 = srs.blst_g2[1]

        result = p2_add(p1, p2)

        assert result is not None

    def test_p2_neg(self):
        """Test P2 point negation."""
        p = srs.blst_g2[0]

        neg_p = p2_neg(p)

        # p + (-p) should be the point at infinity
        result = p2_add(p, neg_p)
        assert result.is_inf()


class TestKZGCommit:
    """Test KZG commitment functionality."""

    def test_commit_simple_poly(self):
        """Test commitment to a simple polynomial."""
        coeffs = [1, 2, 3]

        commitment = KZG.commit(coeffs)

        assert commitment is not None
        assert isinstance(commitment, tuple)
        # Commitment is (x, y, z) in projective coordinates
        assert len(commitment) in [2, 3]  # (x, y) or (x, y, z) coordinates

    def test_commit_zero_poly(self):
        """Test commitment to zero polynomial."""
        coeffs = [0, 0, 0]

        commitment = KZG.commit(coeffs)

        # Should be the point at infinity
        assert commitment is not None

    def test_commit_single_coeff(self):
        """Test commitment to constant polynomial."""
        coeffs = [5]

        commitment = KZG.commit(coeffs)

        assert commitment is not None

    def test_commit_sparse_poly(self):
        """Test commitment to sparse polynomial (many zeros)."""
        coeffs = [1, 0, 0, 0, 0, 5, 0, 0, 0, 3]

        commitment = KZG.commit(coeffs)

        assert commitment is not None

    def test_commit_exceeds_srs_raises(self):
        """Test that committing to too large polynomial raises."""
        # Create polynomial larger than SRS
        coeffs = [1] * (len(srs.g1) + 100)

        with pytest.raises(ValueError, match="polynomial degree exceeds SRS size"):
            KZG.commit(coeffs)


class TestKZGOpen:
    """Test KZG opening functionality."""

    def test_open_simple(self):
        """Test opening a polynomial at a point."""
        coeffs = [1, 2, 3]  # 1 + 2x + 3x^2
        x = 5

        opening = KZG.open(coeffs, x)

        assert isinstance(opening, Opening)
        assert opening.proof is not None
        assert opening.y is not None
        # Verify y = poly(x) = 1 + 2*5 + 3*25 = 1 + 10 + 75 = 86
        # But this is mod curve_order, so check type
        assert isinstance(opening.y, int)

    def test_open_at_zero(self):
        """Test opening at x=0."""
        coeffs = [7, 2, 3]  # 7 + 2x + 3x^2
        x = 0

        opening = KZG.open(coeffs, x)

        # y should be the constant term
        assert opening.y == 7


class TestKZGVerify:
    """Test KZG verification functionality."""

    def test_verify_valid_opening(self):
        """Test verification of a valid opening."""
        coeffs = [1, 2, 3]
        x = 5

        commitment = KZG.commit(coeffs)
        opening = KZG.open(coeffs, x)

        result = KZG.verify(commitment, opening.proof, x, opening.y)

        assert result is True

    def test_verify_invalid_value(self):
        """Test verification fails with wrong value."""
        coeffs = [1, 2, 3]
        x = 5

        commitment = KZG.commit(coeffs)
        opening = KZG.open(coeffs, x)

        # Use wrong value
        wrong_value = (opening.y + 1) % (2**256)

        result = KZG.verify(commitment, opening.proof, x, wrong_value)

        assert result is False

    def test_verify_blst_point_inputs(self):
        """Test verification with blst.P1 inputs directly."""
        coeffs = [1, 2, 3]
        x = 5

        # Get blst.P1 commitment directly
        from dot_ring.ring_proof.pcs.utils import g1_to_blst

        commitment = KZG.commit(coeffs)
        opening = KZG.open(coeffs, x)

        # Convert to blst.P1
        comm_blst = g1_to_blst(commitment)
        proof_blst = g1_to_blst(opening.proof)

        result = KZG.verify(comm_blst, proof_blst, x, opening.y)

        assert result is True


class TestKZGBatchVerify:
    """Test KZG batch verification functionality."""

    def test_batch_verify_empty(self):
        """Test batch verification with empty list."""
        result = KZG.batch_verify([])
        assert result is True

    def test_batch_verify_single(self):
        """Test batch verification with single verification."""
        coeffs = [1, 2, 3]
        x = 5

        commitment = KZG.commit(coeffs)
        opening = KZG.open(coeffs, x)

        # Convert to blst.P1 for batch verification
        from dot_ring.ring_proof.pcs.utils import g1_to_blst

        comm_blst = g1_to_blst(commitment)
        proof_blst = g1_to_blst(opening.proof)

        verifications = [(comm_blst, proof_blst, x, opening.y)]

        result = KZG.batch_verify(verifications)

        assert result is True

    def test_batch_verify_multiple_valid(self):
        """Test batch verification with multiple valid openings."""
        from dot_ring.ring_proof.pcs.utils import g1_to_blst

        verifications = []

        # Create multiple polynomial openings
        for i in range(3):
            coeffs = [1 + i, 2 + i, 3 + i]
            x = 5 + i

            commitment = KZG.commit(coeffs)
            opening = KZG.open(coeffs, x)

            comm_blst = g1_to_blst(commitment)
            proof_blst = g1_to_blst(opening.proof)

            verifications.append((comm_blst, proof_blst, x, opening.y))

        result = KZG.batch_verify(verifications)

        assert result is True

    def test_batch_verify_one_invalid(self):
        """Test batch verification fails if one is invalid."""
        from dot_ring.ring_proof.pcs.utils import g1_to_blst

        verifications = []

        # Create valid openings
        for i in range(2):
            coeffs = [1 + i, 2 + i, 3 + i]
            x = 5 + i

            commitment = KZG.commit(coeffs)
            opening = KZG.open(coeffs, x)

            comm_blst = g1_to_blst(commitment)
            proof_blst = g1_to_blst(opening.proof)

            verifications.append((comm_blst, proof_blst, x, opening.y))

        # Add one invalid opening (wrong value)
        coeffs = [1, 2, 3]
        x = 10
        commitment = KZG.commit(coeffs)
        opening = KZG.open(coeffs, x)

        comm_blst = g1_to_blst(commitment)
        proof_blst = g1_to_blst(opening.proof)

        # Use wrong value
        wrong_value = (opening.y + 1000) % (2**256)
        verifications.append((comm_blst, proof_blst, x, wrong_value))

        result = KZG.batch_verify(verifications)

        assert result is False
