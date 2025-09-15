#!/usr/bin/env python3
"""
Validate Weierstrass curve parameters and operations for:
- P-256 (secp256r1)
- P-384 (secp384r1)
- P-521 (secp521r1)
- secp256k1 (Bitcoin's curve)
"""
import unittest
from typing import Type, Any, Optional, Tuple
from dot_ring.curve.specs.p256 import P256Point, P256Params
from dot_ring.curve.specs.p384 import P384Point, P384Params
from dot_ring.curve.specs.p521 import P521Point, P521Params
from dot_ring.curve.specs.secp256k1 import Secp256k1Point, Secp256k1Params

class WeierstrassCurveTestMixin:
    """Mixin for testing Weierstrass curve implementations."""
    
    PointClass: Type[Any]
    ParamsClass: Type[Any]
    
    def get_curve_parameters(self) -> Tuple[int, int, int, int, int, int]:
        """Get curve parameters in a consistent way across different curve types."""
        params = self.ParamsClass()
        p = params.PRIME_FIELD
        a = params.WEIERSTRASS_A if hasattr(params, 'WEIERSTRASS_A') else -3  # Default to -3 for NIST curves
        b = params.WEIERSTRASS_B if hasattr(params, 'WEIERSTRASS_B') else (
            int("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16) if self.ParamsClass == P256Params else
            int("b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef", 16) if self.ParamsClass == P384Params else
            int("051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00", 16)  # P-521
        )
        Gx = params.GENERATOR_X
        Gy = params.GENERATOR_Y
        n = params.ORDER
        return p, a, b, Gx, Gy, n
    
    def test_curve_parameters(self):
        """Test that curve parameters are valid."""
        try:
            p, a, b, Gx, Gy, n = self.get_curve_parameters()
            
            # Check that the generator point is on the curve
            left = (Gy * Gy) % p
            right = (pow(Gx, 3, p) + a * Gx + b) % p
            self.assertEqual(left, right, "Generator point is not on the curve")
            
            # Check that the curve is non-singular
            discriminant = (4 * a * a * a + 27 * b * b) % p
            self.assertNotEqual(discriminant, 0, "Curve is singular")
            
            # Check that the cofactor is small (security requirement)
            cofactor = self.ParamsClass().COFACTOR
            self.assertLessEqual(cofactor, 0xFF, "Cofactor is too large")
            
        except Exception as e:
            self.fail(f"Curve parameter validation failed: {e}")
    
    def test_point_addition(self):
        """Test point addition and doubling."""
        try:
            G = self.PointClass.generator_point()
            
            # Test identity + G = G
            identity = self.PointClass.identity()
            self.assertEqual(identity + G, G, "Identity + G should equal G")
            
            # Test G + identity = G
            self.assertEqual(G + identity, G, "G + Identity should equal G")
            
            # Test G + (-G) = identity
            G_neg = -G
            result = G + G_neg
            self.assertTrue(result.is_identity(), 
                         f"G + (-G) should equal identity, got {result}")
            
            # Test point doubling 2G = G + G
            G2 = G + G
            self.assertTrue(G2.is_on_curve(), "2G is not on the curve")
            
            # Test that G + G = 2*G
            G2_mul = G * 2
            self.assertEqual(G2, G2_mul, "G + G should equal 2*G")
            
        except Exception as e:
            self.fail(f"Point addition test failed: {e}")
    
    def test_scalar_multiplication(self):
        """Test scalar multiplication."""
        try:
            G = self.PointClass.generator_point()
            n = self.ParamsClass().ORDER
            
            # Test scalar multiplication
            G2 = G * 2
            G2_add = G + G
            self.assertEqual(G2, G2_add, "2*G should equal G + G")
            
            # Test that n*G = identity (point at infinity)
            nG = G * n
            self.assertTrue(nG.is_identity(), f"n*G should be the identity point, got {nG}")
            
        except Exception as e:
            self.fail(f"Scalar multiplication test failed: {e}")


class TestP256(unittest.TestCase, WeierstrassCurveTestMixin):
    """Test P-256 (secp256r1) curve."""
    PointClass = P256Point
    ParamsClass = P256Params


class TestP384(unittest.TestCase, WeierstrassCurveTestMixin):
    """Test P-384 (secp384r1) curve."""
    PointClass = P384Point
    ParamsClass = P384Params


class TestP521(unittest.TestCase, WeierstrassCurveTestMixin):
    """Test P-521 (secp521r1) curve."""
    PointClass = P521Point
    ParamsClass = P521Params


class TestSecp256k1(unittest.TestCase, WeierstrassCurveTestMixin):
    """Test secp256k1 (Bitcoin) curve."""
    PointClass = Secp256k1Point
    ParamsClass = Secp256k1Params


def run_weierstrass_tests():
    """Run all Weierstrass curve tests and print results."""
    print("Validating Weierstrass curves...")
    test_suite = unittest.TestLoader().loadTestsFromTestCase(TestP256)
    test_suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TestP384))
    test_suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TestP521))
    test_suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TestSecp256k1))
    
    test_runner = unittest.TextTestRunner(verbosity=2)
    return test_runner.run(test_suite)


if __name__ == "__main__":
    run_weierstrass_tests()
