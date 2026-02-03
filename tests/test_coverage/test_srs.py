"""Additional tests for SRS module to improve coverage."""

from dot_ring.ring_proof.pcs.srs import SRS, srs


class TestSRS:
    """Test SRS (Structured Reference String) functionality."""

    def test_srs_g1_loaded(self):
        """Test SRS G1 points are loaded."""
        assert srs.blst_g1 is not None
        assert len(srs.blst_g1) > 0

    def test_srs_g2_loaded(self):
        """Test SRS G2 points are loaded."""
        assert srs.blst_g2 is not None

    def test_srs_g1_first_element(self):
        """Test first G1 element is generator."""
        g1 = srs.blst_g1[0]
        assert g1 is not None
        assert not g1.is_inf()

    def test_srs_tau_g1_length(self):
        """Test tau G1 has sufficient length."""
        # Should have enough points for polynomial commitment
        assert len(srs.blst_g1) >= 512

    def test_srs_can_access_multiple_points(self):
        """Test accessing multiple SRS points."""
        for i in range(10):
            point = srs.blst_g1[i]
            assert point is not None


class TestSRSClass:
    """Test SRS class methods."""

    def test_srs_instance(self):
        """Test SRS singleton instance."""
        assert srs is not None
        assert isinstance(srs, SRS)
