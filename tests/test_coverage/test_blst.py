"""Additional tests for blst module to improve coverage."""

from dot_ring import blst


class TestBLSTBasics:
    """Test basic BLST functionality."""

    def test_p1_generator(self):
        """Test P1 generator."""
        g1 = blst.G1()
        assert g1 is not None
        assert not g1.is_inf()

    def test_p1_infinity(self):
        """Test P1 infinity."""
        inf = blst.P1()
        assert inf.is_inf()

    def test_p1_add(self):
        """Test P1 addition."""
        g1 = blst.G1()
        g1_2 = blst.P1()
        g1_2.add(g1)
        g1_2.add(g1)
        assert not g1_2.is_inf()

    def test_p2_generator(self):
        """Test P2 generator."""
        g2 = blst.G2()
        assert g2 is not None
        assert not g2.is_inf()

    def test_p2_infinity(self):
        """Test P2 infinity."""
        inf = blst.P2()
        assert inf.is_inf()

    def test_scalar_creation(self):
        """Test scalar creation."""
        scalar = blst.Scalar()
        assert scalar is not None


class TestBLSTOperations:
    """Test BLST operations."""

    def test_p1_dup(self):
        """Test P1 duplication."""
        g1 = blst.G1()
        g1_dup = g1.dup()
        assert not g1_dup.is_inf()

    def test_p1_neg(self):
        """Test P1 negation."""
        g1 = blst.G1()
        g1.neg()
        assert not g1.is_inf()

    def test_p1_to_affine(self):
        """Test P1 to affine conversion."""
        g1 = blst.G1()
        g1_affine = g1.to_affine()
        assert g1_affine is not None

    def test_p2_dup(self):
        """Test P2 duplication."""
        g2 = blst.G2()
        g2_dup = g2.dup()
        assert not g2_dup.is_inf()

    def test_p2_neg(self):
        """Test P2 negation."""
        g2 = blst.G2()
        g2.neg()
        assert not g2.is_inf()

    def test_p2_to_affine(self):
        """Test P2 to affine conversion."""
        g2 = blst.G2()
        g2_affine = g2.to_affine()
        assert g2_affine is not None


class TestBLSTSerialization:
    """Test BLST serialization."""

    def test_p1_serialize(self):
        """Test P1 serialization."""
        g1 = blst.G1()
        serialized = g1.serialize()
        assert len(serialized) == 96

    def test_p1_compress(self):
        """Test P1 compression."""
        g1 = blst.G1()
        compressed = g1.compress()
        assert len(compressed) == 48

    def test_p2_serialize(self):
        """Test P2 serialization."""
        g2 = blst.G2()
        serialized = g2.serialize()
        assert len(serialized) == 192

    def test_p2_compress(self):
        """Test P2 compression."""
        g2 = blst.G2()
        compressed = g2.compress()
        assert len(compressed) == 96
