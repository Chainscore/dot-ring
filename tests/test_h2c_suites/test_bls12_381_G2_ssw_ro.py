import json
import os
import unittest

from dot_ring.curve.fp2 import Fp2
from dot_ring.curve.specs.bls12_381_G2 import BLS12_381_G2_RO


class TestBLS12_381_G2_SSWU_RO(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Load test vectors
        test_vectors_path = os.path.join(os.path.dirname(__file__), "../vectors/h2c", "bls12_381_G2_ro.json")
        with open(test_vectors_path) as f:
            cls.test_vectors = json.load(f)

    def hex_to_int(self, hex_str, p):
        hex_str = hex_str.lower().replace("0x", "")
        return int(hex_str, 16) % p

    def hex_to_fp2(self, value, p):
        return Fp2(self.hex_to_int(value["re"], p), self.hex_to_int(value["im"], p), p)

    def test_sswu_hash2_curve(self):
        """Test SSWU hash-to-curve for BLS12-381 G2"""
        for i, vector in enumerate(self.test_vectors["vectors"]):
            with self.subTest(f"Test Vector {i + 1}"):
                msg = vector["msg"]
                expected_P = vector["P"]

                # Get the prime modulus for Fp
                p = BLS12_381_G2_RO.curve.params.field_modulus

                # Encode message to curve
                computed_P = BLS12_381_G2_RO.encode_to_curve(msg.encode("utf-8"), b"")

                # Create sample.py P point
                expected_P_x = self.hex_to_fp2(expected_P["x"], p)
                expected_P_y = self.hex_to_fp2(expected_P["y"], p)

                assert expected_P_x == computed_P.x, "P.x does not match"
                assert expected_P_y == computed_P.y, "P.y does not match"


if __name__ == "__main__":
    unittest.main()
