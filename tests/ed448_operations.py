#!/usr/bin/env python3
"""
Test operations for Ed448 (Twisted Edwards form of Curve448).

This script demonstrates point operations, serialization, and deserialization
for the Ed448 curve as defined in RFC 8032.
"""

import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dot_ring.curve.specs.ed448 import Ed448Point, Ed448Params


def multiply_and_print(scalar: int, point_name: str = "G") -> None:
    """
    Multiply the generator point by a scalar, print the result, and demonstrate serialization.

    Args:
        scalar: The scalar to multiply the generator by
        point_name: Name to display for the resulting point
    """
    G = Ed448Point.generator_point()
    result = G * scalar

    print(f"\n{point_name} = {scalar} * G")
    print(f"x = {result.x}")
    print(f"y = {result.y}")

    # Verify the result is on the curve: -x² + y² = 1 + dx²y²
    p = Ed448Params.PRIME_FIELD
    x = result.x
    y = result.y

    if x is None or y is None:
        print("Result is point at infinity")
        return

    left = (x * x + y * y) % p
    right = (1 + Ed448Params.EDWARDS_D * x * x * y * y) % p

    print("\nVerification:")
    print(f"x² + y² mod p         = {left}")
    print(f"1 + dx²y² mod p       = {right}")
    print("✓ Point is on the curve" if left == right else "✗ Point is NOT on the curve!")

    # Demonstrate serialization
    print("\nSerialization:")

    # Serialize the point (Ed448 uses compressed format by default)
    serialized = result.to_bytes()
    print(f"Serialized ({len(serialized)} bytes): {serialized.hex()}")

    # Deserialize the point
    recovered = Ed448Point.from_bytes(serialized)
    print(f"Recovered: x={recovered.x}, y={recovered.y}")

    # Verify recovered point matches original
    assert recovered.x == result.x
    assert recovered.y == result.y

    # For Ed448, also test the identity encoding
    if scalar == Ed448Params.ORDER:
        print("\nTesting identity point encoding:")
        identity_bytes = bytes([0] * 57)  # All-zero encoding for identity
        try:
            identity_point = Ed448Point.from_bytes(identity_bytes)
            print(f"Identity point decoded as: x={identity_point.x}, y={identity_point.y}")
        except Exception as e:
            print(f"Error decoding identity: {e}")


if __name__ == "__main__":
    # Print generator point for reference
    G = Ed448Point.generator_point()
    print(f"Generator point G (Ed448):")
    print(f"x = {G.x}")
    print(f"y = {G.y}")

    # Demonstrate serialization of the generator point
    print("\n--- Serialization Demo for Generator Point ---")
    multiply_and_print(1, "G")

    # Multiply by different scalars
    print("\n--- Multiplication and Serialization Tests ---")
    multiply_and_print(2, "2G")
    multiply_and_print(3, "3G")
    multiply_and_print(10, "10G")

    # Multiply by the curve order (should give point at infinity)
    print("\n--- Edge Case: Multiplying by Curve Order ---")
    print("Multiplying by curve order (should give point at infinity):")
    try:
        multiply_and_print(Ed448Params.ORDER, "ORDER*G")
    except Exception as e:
        print(f"Expected error when serializing point at infinity: {e}")

    # Test the identity point
    print("\n--- Testing Identity Point ---")
    try:
        identity = Ed448Point.identity()
        print(f"Identity point: x={identity.x}, y={identity.y}")
        print(f"Identity serialized: {identity.to_bytes().hex()}")
    except Exception as e:
        print(f"Error with identity point: {e}")