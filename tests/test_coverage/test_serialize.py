"""Additional tests for serialize module to improve coverage."""

from dot_ring.ring_proof.transcript.serialize import serialize


class TestSerialize:
    """Test serialization functions."""

    def test_serialize_int(self):
        """Test serializing an integer."""
        scalar = 12345

        result = serialize(scalar)

        assert result is not None
        assert isinstance(result, bytes)

    def test_serialize_large_int(self):
        """Test serializing a large integer."""
        scalar = 2**200

        result = serialize(scalar)

        assert result is not None
        assert isinstance(result, bytes)

    def test_serialize_zero(self):
        """Test serializing zero."""
        scalar = 0

        result = serialize(scalar)

        assert result is not None
        assert isinstance(result, bytes)

    def test_serialize_list_of_ints(self):
        """Test serializing a list of ints."""
        data = [1, 2, 3]

        result = serialize(data)

        assert result is not None
        assert isinstance(result, bytes)

    def test_serialize_nested_list(self):
        """Test serializing a nested list."""
        data = [[1, 2], [3, 4]]

        result = serialize(data)

        assert result is not None
        assert isinstance(result, bytes)

    def test_serialize_tuple_of_two(self):
        """Test serializing a tuple of two integers (like coordinates)."""
        data = (1, 2)

        result = serialize(data)

        assert result is not None
        assert isinstance(result, bytes)
