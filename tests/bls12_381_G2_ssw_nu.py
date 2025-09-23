import json
import os
import unittest
from dot_ring.curve.specs.bls12_381_G2 import BLS12_381_G2Point
from dot_ring.curve.field_element import FieldElement


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

                print(f"\n--- Test Vector {i + 1} ---")
                print(f"Message: {repr(msg)}")

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

                print("\n--- u values ---")
                print(f"Expected u0: {expected_u0}")
                print(f"Computed u0: {computed_u0}")


                # # Assert u values match
                self.assertEqual(computed_u0, expected_u0, "u0 does not match")


                # Compare Q0
                print("\n--- Q0 ---")
                print(f"Expected x: {expected_Q0_x}")
                print(f"Computed x: {computed_Q0.x}")
                print(f"Expected y: {expected_Q0_y}")
                print(f"Computed y: {computed_Q0.y}")

                # Assert Q0 matches
                self.assertEqual(computed_Q0.x, expected_Q0_x, "Q0.x does not match")
                self.assertEqual(computed_Q0.y, expected_Q0_y, "Q0.y does not match")

                # Compare final result P
                print("\n--- Final Result P ---")
                # Create sample.py P point
                expected_P_x = (self.hex_to_field_element(expected_P['x']['re'], p),
                                self.hex_to_field_element(expected_P['x']['im'], p))
                expected_P_y = (
                    self.hex_to_field_element(expected_P['y']['re'], p),
                    self.hex_to_field_element(expected_P['y']['im'], p))

                print(f"Expected P.x: {expected_P_x}")
                print(f"Computed P.x: {computed_P.x}")
                print(f"Expected P.y: {expected_P_y}")
                print(f"Computed P.y: {computed_P.y}")

                assert expected_P_x == computed_P.x, "P.x does not match"
                assert expected_P_y == computed_P.y, "P.y does not match"

                print("\n✅ All tests passed for this vector!")


if __name__ == "__main__":
    unittest.main()