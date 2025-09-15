#!/usr/bin/env python3
"""
Test operations for Curve25519 implementation.
"""
import unittest
from dot_ring.curve.specs.curve25519 import (
    Curve25519Point,
    curve25519_base_point,
    curve25519_random_scalar,
    Curve25519Params
)

class TestCurve25519Operations(unittest.TestCase):
    """Test cases for Curve25519 operations."""

    def setUp(self):
        """Set up test fixtures."""
        self.G = curve25519_base_point()
        self.identity = Curve25519Point.identity()

    def test_identity_properties(self):
        """Test identity point properties."""
        self.assertTrue(self.identity.is_identity())
        self.assertIsNone(self.identity.x)
        self.assertIsNone(self.identity.y)

    def test_generator_point(self):
        """Test that the generator point is valid."""
        self.assertTrue(self.G.is_on_curve())
        self.assertTrue(self.G.validate_coordinates())

    def test_point_addition(self):
        """Test point addition."""
        G2 = self.G + self.G
        self.assertTrue(G2.is_on_curve())
        self.assertNotEqual((self.G.x, self.G.y), (G2.x, G2.y))

    def test_scalar_multiplication(self):
        """Test scalar multiplication."""
        # Test 2G = G + G
        G2 = self.G * 2
        G2_add = self.G + self.G
        self.assertEqual((G2.x, G2.y), (G2_add.x, G2_add.y))

        # Test 3G = 2G + G
        G3 = self.G * 3
        G3_add = G2 + self.G
        self.assertEqual((G3.x, G3.y), (G3_add.x, G3_add.y))

    def test_x25519_serialization(self):
        """Test X25519 serialization/deserialization."""
        # Test serialization (compressed format - just x-coordinate)
        x25519_bytes = self.G.to_bytes(compressed=True)
        self.assertEqual(len(x25519_bytes), 32)  # 32 bytes for x-coordinate

        # Test deserialization
        G_recovered = Curve25519Point.from_bytes(x25519_bytes, self.G.curve, compressed=True)
        self.assertEqual(G_recovered.x, self.G.x)
        self.assertTrue(G_recovered.is_on_curve())
        
        # Also test uncompressed format for completeness
        uncompressed_bytes = self.G.to_bytes(compressed=False)
        self.assertEqual(len(uncompressed_bytes), 64)  # 32 bytes for x + 32 bytes for y
        
        G_uncompressed = Curve25519Point.from_bytes(uncompressed_bytes, self.G.curve, compressed=False)
        self.assertEqual(G_uncompressed.x, self.G.x)
        self.assertEqual(G_uncompressed.y, self.G.y)
        self.assertTrue(G_uncompressed.is_on_curve())

    def test_order_multiplication(self):
        """Test that multiplying by the group order gives identity."""
        # G * order should be the identity
        order_times_G = self.G * Curve25519Params.ORDER
        self.assertTrue(order_times_G.is_identity())

def run_curve25519_tests():
    """Run all Curve25519 tests and print results."""
    print("Running Curve25519 tests...")
    test_suite = unittest.TestLoader().loadTestsFromTestCase(TestCurve25519Operations)
    test_runner = unittest.TextTestRunner(verbosity=2)
    return test_runner.run(test_suite)

if __name__ == "__main__":
    run_curve25519_tests()
