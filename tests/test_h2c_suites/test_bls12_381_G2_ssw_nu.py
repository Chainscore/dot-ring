import json
import os
import unittest
from dot_ring.curve.specs.bls12_381_G2 import nu_variant
from dot_ring.curve.e2c import E2C_Variant
from dot_ring.curve.field_element import FieldElement

BLS12_381_G2Point = nu_variant(E2C_Variant.SSWU_NU)


class TestBLS12_381_G2_SSWU_RO(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Load test vectors
        test_vectors_path = os.path.join(
            os.path.dirname(__file__),
            'vectors',
            'bls12_381_G2_nu.json'
        )
        with open(test_vectors_path, 'r') as f:
            cls.test_vectors = json.load(f)

    def hex_to_field_element(self, hex_str, p):
        """Convert hex string to integer and create FieldElement"""
        # Remove '0x' prefix if present
        hex_str = hex_str.lower().replace('0x', '')
        # Convert to integer and create FieldElement
        return int(hex_str, 16) % p

    def test_sswu_hash2_curve(self):
        """Test SSWU hash-to-curve for BLS12-381 G2"""
        for i, vector in enumerate(self.test_vectors['vectors']):
            with self.subTest(f"Test Vector {i + 1}"):
                msg = vector['msg']
                expected_P = vector['P']
                expected_Q0 = vector['Q0']
                expected_u = vector['u']

                # Get the prime modulus for Fp
                p = BLS12_381_G2Point.curve.PRIME_FIELD

                # Convert sample.py values to FieldElements
                expected_u0 = (
                    self.hex_to_field_element(expected_u[0]['re'], p),
                    self.hex_to_field_element(expected_u[0]['im'], p)
                )

                # Encode message to curve
                result = BLS12_381_G2Point.encode_to_curve(msg.encode("utf-8"), b"", True)

                # Extract computed values
                computed_P = result["R"]
                computed_Q0 = result["Q0"]
                computed_u0= tuple(result["u"])


                # Create sample.py FieldElement objects for comparison
                expected_Q0_x = FieldElement(
                    self.hex_to_field_element(expected_Q0['x']['re'], p),
                    self.hex_to_field_element(expected_Q0['x']['im'], p),
                    p
                )
                expected_Q0_y = FieldElement(
                    self.hex_to_field_element(expected_Q0['y']['re'], p),
                    self.hex_to_field_element(expected_Q0['y']['im'], p),
                    p
                )
                # # Assert u values match
                self.assertEqual(computed_u0, expected_u0, "u0 does not match")

                # Assert Q0 matches
                self.assertEqual(computed_Q0.x, expected_Q0_x, "Q0.x does not match")
                self.assertEqual(computed_Q0.y, expected_Q0_y, "Q0.y does not match")

                # Create sample.py P point
                expected_P_x = (self.hex_to_field_element(expected_P['x']['re'], p),
                                self.hex_to_field_element(expected_P['x']['im'], p))
                expected_P_y = (
                    self.hex_to_field_element(expected_P['y']['re'], p),
                    self.hex_to_field_element(expected_P['y']['im'], p))

                assert expected_P_x == computed_P.x, "P.x does not match"
                assert expected_P_y == computed_P.y, "P.y does not match"

                print(f"✅ Test Vector{i+1}")


if __name__ == "__main__":
    unittest.main()