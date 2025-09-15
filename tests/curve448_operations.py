from dot_ring.curve.specs.curve448 import Curve448Point, Curve448Params

def multiply_and_print(scalar: int, point_name: str = "G") -> None:
    """
    Multiply the generator point by a scalar, print the result, and demonstrate serialization.
    """
    G = Curve448Point.generator_point()
    result = G * scalar
    
    print(f"\n{point_name} = {scalar} * G")
    print(f"u = {result.x}")
    print(f"v = {result.y}")
    
    # Verify the result is on the curve
    p = Curve448Params.PRIME_FIELD
    u = result.x
    v = result.y
    
    if u is None or v is None:
        print("Result is point at infinity")
        return
    
    left = (v * v) % p
    right = (u**3 + Curve448Params.A * u**2 + u) % p
    
    print("\nVerification:")
    print(f"v² mod p      = {left}")
    print(f"u³ + A·u² + u = {right}")
    print("✓ Point is on the curve" if left == right else "✗ Point is NOT on the curve!")
    
    # Demonstrate serialization
    print("\nSerialization:")
    
    # Serialize to compressed format (just u-coordinate)
    compressed_bytes = result.to_bytes(compressed=True)
    print(f"Compressed ({len(compressed_bytes)} bytes): {compressed_bytes.hex()}")
    
    # Deserialize compressed point
    recovered_compressed = Curve448Point.from_bytes(compressed_bytes, result.curve, compressed=True)
    print(f"Recovered from compressed: u={recovered_compressed.x}, v={recovered_compressed.y}")
    
    # For compressed format, we need to check if we got the correct y-coordinate
    # Since both y and -y are valid, we need to check which one matches our original point
    if recovered_compressed.y != result.y:
        print("  Note: Recovered y-coordinate is the other root (y = -y_original)")
        # The other possible y is -y mod p
        p = Curve448Params.PRIME_FIELD
        other_y = (-recovered_compressed.y) % p
        print(f"  Other possible y: {other_y}")
    
    # Serialize to uncompressed format (both u and v coordinates)
    uncompressed_bytes = result.to_bytes(compressed=False)
    print(f"\nUncompressed ({len(uncompressed_bytes)} bytes): {uncompressed_bytes.hex()}")
    
    # Deserialize uncompressed point
    recovered_uncompressed = Curve448Point.from_bytes(uncompressed_bytes, result.curve, compressed=False)
    print(f"Recovered from uncompressed: u={recovered_uncompressed.x}, v={recovered_uncompressed.y}")
    
    # Verify recovered points match original
    # For compressed format, x should match, and y should be either y or -y
    assert recovered_compressed.x == result.x
    p = Curve448Params.PRIME_FIELD
    assert (recovered_compressed.y == result.y) or (recovered_compressed.y == (-result.y) % p)
    
    # For uncompressed format, both x and y should match exactly
    assert recovered_uncompressed.x == result.x
    assert recovered_uncompressed.y == result.y

if __name__ == "__main__":
    # Print generator point for reference
    G = Curve448Point.generator_point()
    print(f"Generator point G:")
    print(f"u = {G.x}")
    print(f"v = {G.y}")
    
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
        multiply_and_print(Curve448Params.ORDER, "ORDER*G")
    except Exception as e:
        print(f"Expected error when serializing point at infinity: {e}")
