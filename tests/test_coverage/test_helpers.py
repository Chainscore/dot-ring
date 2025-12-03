"""Tests for helpers module to improve coverage."""

import pytest
from py_ecc.optimized_bls12_381 import FQ, FQ2

from dot_ring.ring_proof.helpers import Helpers as H


class TestHelpers:
    """Test cases for Helpers class."""

    def test_knocker_delta_equal(self):
        """Test Kronecker delta for equal indices."""
        assert H.knocker_delta(5, 5) == 1
        assert H.knocker_delta(0, 0) == 1

    def test_knocker_delta_not_equal(self):
        """Test Kronecker delta for unequal indices."""
        assert H.knocker_delta(3, 5) == 0
        assert H.knocker_delta(0, 1) == 0

    def test_unzip_basic(self):
        """Test unzip of point list."""
        points = [(1, 2), (3, 4), (5, 6)]
        x_coords, y_coords = H.unzip(points)
        assert x_coords == [1, 3, 5]
        assert y_coords == [2, 4, 6]

    def test_unzip_empty(self):
        """Test unzip of empty list."""
        x_coords, y_coords = H.unzip([])
        assert x_coords == []
        assert y_coords == []

    def test_unzip_single(self):
        """Test unzip of single point."""
        points = [(10, 20)]
        x_coords, y_coords = H.unzip(points)
        assert x_coords == [10]
        assert y_coords == [20]

    def test_to_int(self):
        """Test conversion to int tuple."""
        tup = (FQ(123), FQ(456))
        result = H.to_int(tup)
        assert result == (123, 456)

    def test_to_bytes(self):
        """Test int to hex string conversion."""
        val = 0x12345
        result = H.to_bytes(val)
        # Should be 32 bytes little-endian hex
        assert len(result) == 64  # 32 bytes * 2 hex chars
        assert isinstance(result, str)

    def test_to_scalar_int_bytes(self):
        """Test bytes to scalar int conversion."""
        data = b"\x01\x02\x03\x04"
        result = H.to_scalar_int(data)
        expected = int.from_bytes(data, "little")
        assert result == expected

    def test_to_scalar_int_hex_string(self):
        """Test hex string to scalar int conversion."""
        hex_str = "01020304"
        result = H.to_scalar_int(hex_str)
        expected = int.from_bytes(bytes.fromhex(hex_str), "little")
        assert result == expected

    def test_l_endian_2_int_bytes(self):
        """Test little-endian bytes to int."""
        data = b"\x01\x02\x03\x04"
        result = H.l_endian_2_int(data)
        expected = int.from_bytes(data, "little")
        assert result == expected

    def test_l_endian_2_int_hex_string(self):
        """Test little-endian hex string to int."""
        hex_str = "01020304"
        result = H.l_endian_2_int(hex_str)
        expected = int.from_bytes(bytes.fromhex(hex_str), "little")
        assert result == expected

    def test_b_endian_2_int_bytes(self):
        """Test big-endian bytes to int."""
        data = b"\x01\x02\x03\x04"
        result = H.b_endian_2_int(data)
        expected = int.from_bytes(data, "big")
        assert result == expected

    def test_b_endian_2_int_hex_string(self):
        """Test big-endian hex string to int."""
        hex_str = "01020304"
        result = H.b_endian_2_int(hex_str)
        expected = int.from_bytes(bytes.fromhex(hex_str), "big")
        assert result == expected

    def test_str_to_int_little(self):
        """Test str_to_int with little endian."""
        data = b"\x01\x02\x03\x04"
        result = H.str_to_int(data, "little")
        expected = int.from_bytes(data, "little")
        assert result == expected

    def test_str_to_int_big(self):
        """Test str_to_int with big endian."""
        data = b"\x01\x02\x03\x04"
        result = H.str_to_int(data, "big")
        expected = int.from_bytes(data, "big")
        assert result == expected

    def test_str_to_int_hex_string_little(self):
        """Test str_to_int with hex string and little endian."""
        hex_str = "01020304"
        result = H.str_to_int(hex_str, "little")  # type: ignore
        expected = int.from_bytes(bytes.fromhex(hex_str), "little")
        assert result == expected

    def test_str_to_int_hex_string_big(self):
        """Test str_to_int with hex string and big endian."""
        hex_str = "01020304"
        result = H.str_to_int(hex_str, "big")  # type: ignore
        expected = int.from_bytes(bytes.fromhex(hex_str), "big")
        assert result == expected

    def test_int_to_str_little(self):
        """Test int_to_str with little endian."""
        val = 0x12345678
        result = H.int_to_str(val, "little", 4)
        expected = val.to_bytes(4, "little")
        assert result == expected

    def test_int_to_str_big(self):
        """Test int_to_str with big endian."""
        val = 0x12345678
        result = H.int_to_str(val, "big", 4)
        expected = val.to_bytes(4, "big")
        assert result == expected

    def test_int_to_str_default_length(self):
        """Test int_to_str with default 32-byte length."""
        val = 0x12345
        result = H.int_to_str(val, "little")
        assert len(result) == 32
        assert int.from_bytes(result, "little") == val

    def test_to_b_endian(self):
        """Test to_b_endian conversion."""
        val = 0x12345678
        result = H.to_b_endian(val, 4)
        expected = val.to_bytes(4, "big")
        assert result == expected

    def test_to_b_endian_default_length(self):
        """Test to_b_endian with default length."""
        val = 0x12345
        result = H.to_b_endian(val)
        assert len(result) == 32

    def test_to_l_endian(self):
        """Test to_l_endian conversion."""
        val = 0x12345678
        result = H.to_l_endian(val, 4)
        expected = val.to_bytes(4, "little")
        assert result == expected

    def test_to_l_endian_default_length(self):
        """Test to_l_endian with default length."""
        val = 0x12345
        result = H.to_l_endian(val)
        assert len(result) == 32

    def test_pt_len(self):
        """Test pt_len calculation."""
        # For a prime with bit_length n, coord_size = (n + 7) // 8
        prime = 0xFFFF  # 16 bits -> 2 bytes
        result = H.pt_len(prime)
        assert result == 2

        # Larger prime
        prime = (1 << 256) - 1  # 256 bits -> 32 bytes
        result = H.pt_len(prime)
        assert result == 32

    def test_to_fq(self):
        """Test conversion to FQ tuple."""
        point = (123, 456, 1)
        result = H.to_fq(point)
        assert isinstance(result[0], FQ)
        assert isinstance(result[1], FQ)
        assert isinstance(result[2], FQ)
        assert int(result[0]) == 123
        assert int(result[1]) == 456
        assert int(result[2]) == 1

    def test_bls_projective_2_affine(self):
        """Test projective to affine conversion."""
        points_3d = [(1, 2, 3), (4, 5, 6), (7, 8, 9)]
        result = H.bls_projective_2_affine(points_3d)
        assert result == [(1, 2), (4, 5), (7, 8)]

    def test_bls_projective_2_affine_empty(self):
        """Test projective to affine with empty list."""
        result = H.bls_projective_2_affine([])
        assert result == []

    def test_altered_points(self):
        """Test altered_points for G2 points."""
        # G2 points structure: list of pairs where each pair has points with (a, b) coords
        g2_points = [[((1, 2), (3, 4))]]
        result = H.altered_points(g2_points)
        # Should swap coordinates
        assert len(result) > 0


class TestBLSCompression:
    """Test BLS point compression/decompression."""

    def test_bls_g1_compress_affine(self):
        """Test G1 point compression with 2D affine coordinates."""
        # Use a known valid BLS12-381 G1 point (the generator)
        # This is the generator point of BLS12-381 G1
        x = 3685416753713387016781088315183077757961620795782546409894578378688607592378376318836054947676345821548104185464507
        y = 1339506544944476473020471379941921221584933875938349620426543736416511423956333506472724655353366534992391756441569
        
        point = (x, y)
        result = H.bls_g1_compress(point)
        
        assert isinstance(result, str)
        assert len(result) == 96  # 48 bytes in hex

    def test_bls_g1_compress_projective(self):
        """Test G1 point compression with 3D projective coordinates."""
        x = 3685416753713387016781088315183077757961620795782546409894578378688607592378376318836054947676345821548104185464507
        y = 1339506544944476473020471379941921221584933875938349620426543736416511423956333506472724655353366534992391756441569
        z = 1
        
        point = (x, y, z)
        result = H.bls_g1_compress(point)
        
        assert isinstance(result, str)
        assert len(result) == 96

    def test_bls_g1_decompress_bytes(self):
        """Test G1 point decompression from bytes."""
        # Compress a point first, then decompress
        x = 3685416753713387016781088315183077757961620795782546409894578378688607592378376318836054947676345821548104185464507
        y = 1339506544944476473020471379941921221584933875938349620426543736416511423956333506472724655353366534992391756441569
        
        point = (x, y)
        compressed_hex = H.bls_g1_compress(point)
        compressed_bytes = bytes.fromhex(compressed_hex)
        
        result = H.bls_g1_decompress(compressed_bytes)
        
        assert isinstance(result, tuple)
        assert len(result) == 3  # (FQ, FQ, FQ)

    def test_bls_g1_decompress_hex_string(self):
        """Test G1 point decompression from hex string."""
        x = 3685416753713387016781088315183077757961620795782546409894578378688607592378376318836054947676345821548104185464507
        y = 1339506544944476473020471379941921221584933875938349620426543736416511423956333506472724655353366534992391756441569
        
        point = (x, y)
        compressed_hex = H.bls_g1_compress(point)
        
        result = H.bls_g1_decompress(compressed_hex)
        
        assert isinstance(result, tuple)
        assert len(result) == 3

    def test_bls_g2_compress_projective(self):
        """Test G2 point compression with projective coordinates."""
        # Use a simple G2 point structure
        # G2 points have FQ2 coordinates
        from py_ecc.optimized_bls12_381 import G2
        
        result = H.bls_g2_compress(G2)
        
        assert isinstance(result, str)
        assert len(result) == 192  # 96 bytes in hex (2x 48 bytes)

    def test_bls_g2_compress_affine(self):
        """Test G2 point compression with affine coordinates."""
        from py_ecc.optimized_bls12_381 import G2, normalize
        
        # Normalize to get affine coordinates
        g2_affine = normalize(G2)
        x, y = g2_affine
        
        # Create 2D point
        point = (x, y)
        result = H.bls_g2_compress(point)
        
        assert isinstance(result, str)
        assert len(result) == 192
