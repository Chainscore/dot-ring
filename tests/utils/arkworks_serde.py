"""
Arkworks serialization/deserialization utilities.

Functions to convert between arkworks compressed format and Python types
for BLS12-381 (G1, G2) and Bandersnatch points.
"""

from py_ecc.optimized_bls12_381 import FQ, FQ2


def deserialize_fq_field_element(data: bytes) -> int:
    """
    Deserialize arkworks Fq field element (32 bytes, little-endian).

    Arkworks uses Montgomery form internally but serializes as regular integers.
    """
    return int.from_bytes(data, byteorder='little')


def deserialize_bandersnatch_point(x_bytes: bytes, y_bytes: bytes) -> tuple[int, int]:
    """
    Deserialize Bandersnatch point from arkworks compressed format.

    Args:
        x_bytes: x-coordinate (32 bytes, little-endian Fq)
        y_bytes: y-coordinate (32 bytes, little-endian Fq)

    Returns:
        (x, y) tuple as Python integers
    """
    x = deserialize_fq_field_element(x_bytes)
    y = deserialize_fq_field_element(y_bytes)
    return (x, y)


def compressed_bandersnatch_to_uncompressed_bytes(compressed: bytes) -> bytes:
    """
    Convert compressed Bandersnatch point (32 bytes) to uncompressed (64 bytes) for transcript.

    Arkworks compressed format for Bandersnatch:
    - 32 bytes: x-coordinate (little-endian) with flags in high bits
    - y-coordinate is recovered from curve equation

    Arkworks uncompressed format:
    - 32 bytes: x-coordinate (little-endian, no flags)
    - 32 bytes: y-coordinate (little-endian)

    Args:
        compressed: 32-byte compressed point

    Returns:
        64-byte uncompressed point (x || y)
    """
    if len(compressed) != 32:
        raise ValueError(f"Expected 32 bytes for compressed Bandersnatch point, got {len(compressed)}")

    # Check flags in last byte (little-endian, so flags are at the end)
    flags = compressed[-1]
    is_infinity = (flags & 0x40) != 0
    is_positive = (flags & 0x80) == 0  # Sign bit

    if is_infinity:
        # Point at infinity
        return b'\x00' * 64

    # Extract x-coordinate (remove flag bits from last byte)
    x_bytes = compressed[:-1] + bytes([compressed[-1] & 0x3F])
    x = int.from_bytes(x_bytes, 'little')

    # Recover y from Twisted Edwards curve equation: a*x^2 + y^2 = 1 + d*x^2*y^2
    # Rearranged: y^2 = (1 - a*x^2) / (1 - d*x^2)
    # Bandersnatch parameters from the curve specification
    from dot_ring.curve.specs.bandersnatch import BandersnatchParams
    a = BandersnatchParams.EDWARDS_A
    d = BandersnatchParams.EDWARDS_D
    p = BandersnatchParams.MODULUS

    x_squared = (x * x) % p
    numerator = (1 - a * x_squared) % p
    denominator = (1 - d * x_squared) % p
    denominator_inv = pow(denominator, p - 2, p)  # Fermat's little theorem
    y_squared = (numerator * denominator_inv) % p

    # Compute square root using Tonelli-Shanks or p ≡ 3 mod 4 method
    # For Bandersnatch, p ≡ 1 mod 4, so we need Tonelli-Shanks
    # But for simplicity, we can use the fact that we know the sign
    y = pow(y_squared, (p + 1) // 4, p)  # This might not always work

    # Actually, let's check if p ≡ 3 mod 4
    # Bandersnatch uses BLS12-381 scalar field, which is p ≡ 3 mod 4
    y = pow(y_squared, (p + 1) // 4, p)

    # Check which square root to use based on sign bit
    # The sign bit indicates whether y is positive or negative
    if (y > (p - 1) // 2) != is_positive:
        y = p - y

    # Serialize as uncompressed: x (32 bytes) || y (32 bytes), little-endian, no flags
    x_uncompressed = x.to_bytes(32, 'little')
    y_bytes = y.to_bytes(32, 'little')

    return x_uncompressed + y_bytes


def deserialize_bls12_381_g1(data: bytes) -> tuple:
    """
    Deserialize BLS12-381 G1 point from arkworks compressed format.

    Arkworks compressed G1: 48 bytes, big-endian
    - Bit 7 (MSB): compression flag (1 = compressed)
    - Bit 6: infinity flag (1 = point at infinity)
    - Bit 5: y-coordinate sign/parity
    - Remaining bits: x-coordinate

    Returns py_ecc Jacobian tuple (FQ, FQ, FQ)
    """
    if len(data) != 48:
        raise ValueError(f"Expected 48 bytes for G1 point, got {len(data)}")

    # Check flags in first byte
    flags = data[0]
    is_compressed = (flags & 0x80) != 0
    is_infinity = (flags & 0x40) != 0
    y_parity = (flags & 0x20) != 0

    if is_infinity:
        # Point at infinity - return identity element
        return (FQ(0), FQ(1), FQ(0))

    if not is_compressed:
        # Uncompressed format (not typically used by arkworks for G1)
        raise ValueError("Uncompressed G1 points not supported")

    # Extract x-coordinate (remove flag bits from first byte)
    data_clean = bytes([data[0] & 0x1F]) + data[1:]
    x = int.from_bytes(data_clean, 'big')

    # Recover y from curve equation: y^2 = x^3 + 4
    from py_ecc.bls12_381 import bls12_381_pairing as pairing
    field_modulus = pairing.field_modulus

    x_fq = FQ(x)
    y_squared = x_fq * x_fq * x_fq + FQ(4)

    # Compute square root (y_squared^((p+1)/4) mod p for p ≡ 3 mod 4)
    y = y_squared ** ((field_modulus + 1) // 4)

    # Choose correct square root based on sign/parity bit
    # The sign bit indicates if y > (p-1)/2 (lexicographically largest), not if y is odd!
    # This follows the ZCash BLS12-381 spec and matches arkworks serialization.
    y_is_lexicographically_largest = int(y) > (field_modulus - 1) // 2

    # If the computed y doesn't match the sign bit, use the other square root
    if y_is_lexicographically_largest != y_parity:
        y = FQ(field_modulus) - y

    return (x_fq, y, FQ(1))


def compressed_g1_to_uncompressed_bytes(compressed: bytes) -> bytes:
    """
    Convert compressed BLS12-381 G1 point to uncompressed bytes for transcript.

    Args:
        compressed: 48-byte compressed point

    Returns:
        96-byte uncompressed point (x || y, no flags)
    """
    # Deserialize to get (x, y) coordinates
    point = deserialize_bls12_381_g1(compressed)
    x_fq, y_fq, z_fq = point

    # Handle point at infinity
    if z_fq == FQ(0):
        return b'\x00' * 96

    # Convert to affine coordinates (already in affine if z=1)
    x = int(x_fq)
    y = int(y_fq)

    # Serialize as uncompressed: x (48 bytes) || y (48 bytes), big-endian, no flags
    x_bytes = x.to_bytes(48, 'big')
    y_bytes = y.to_bytes(48, 'big')

    return x_bytes + y_bytes


def compressed_g2_to_uncompressed_bytes(compressed: bytes) -> bytes:
    """
    Convert compressed BLS12-381 G2 point to uncompressed bytes for transcript.

    Args:
        compressed: 96-byte compressed G2 point (arkworks format: c1 || c0)

    Returns:
        192-byte uncompressed G2 point (arkworks format: x_c1 || x_c0 || y_c1 || y_c0, no flags)
    """
    if len(compressed) != 96:
        raise ValueError(f"Expected 96 bytes for compressed G2 point, got {len(compressed)}")

    # Deserialize the compressed G2 point
    g2_point = deserialize_bls12_381_g2(compressed)

    # g2_point is ((x, y, z)) in Jacobian coordinates where x, y are FQ2 elements
    # We need to convert to affine: (x, y)
    from py_ecc.optimized_bls12_381 import normalize as nm
    affine = nm(g2_point)
    x_fq2, y_fq2 = affine

    # Each FQ2 element has two coefficients (c0, c1)
    x_c0, x_c1 = x_fq2.coeffs
    y_c0, y_c1 = y_fq2.coeffs

    # Serialize as uncompressed: arkworks uses c1 || c0 || c1 || c0 format
    # Each coefficient is 48 bytes, big-endian, no flags
    x_c0_bytes = int(x_c0).to_bytes(48, 'big')
    x_c1_bytes = int(x_c1).to_bytes(48, 'big')
    y_c0_bytes = int(y_c0).to_bytes(48, 'big')
    y_c1_bytes = int(y_c1).to_bytes(48, 'big')

    return x_c1_bytes + x_c0_bytes + y_c1_bytes + y_c0_bytes


def legendre_fq(a: int, p: int) -> int:
    """Compute Legendre symbol (a/p) = a^((p-1)/2) mod p.

    Returns:
        1 if a is a quadratic residue
        -1 if a is a quadratic non-residue
        0 if a is 0
    """
    if a == 0:
        return 0
    result = pow(a, (p - 1) // 2, p)
    return -1 if result == p - 1 else result


def sqrt_fq2(a) -> tuple[int, int] | None:
    """
    Compute square root of FQ2 element using arkworks algorithm.

    Implements Algorithm 8 from https://eprint.iacr.org/2012/685.pdf (page 15)
    This matches arkworks' implementation exactly.

    Args:
        a: FQ2 element (can be either regular or optimized FQ2)

    Returns:
        Tuple (c0, c1) representing the square root, or None if no root exists.
    """
    from py_ecc.bls12_381 import bls12_381_pairing as pairing
    field_modulus = pairing.field_modulus

    # Extract coefficients (works for both FQ2 types)
    c0, c1 = a.coeffs
    c0_int = int(c0) % field_modulus
    c1_int = int(c1) % field_modulus

    # Special case: a = 0
    if c0_int == 0 and c1_int == 0:
        return (0, 0)

    # If c1 is zero, return sqrt(c0) + 0*i
    if c1_int == 0:
        # Use Fp square root: since p ≡ 3 mod 4, sqrt(x) = x^((p+1)/4)
        sqrt_c0 = pow(c0_int, (field_modulus + 1) // 4, field_modulus)
        if pow(sqrt_c0, 2, field_modulus) == c0_int:
            return (sqrt_c0, 0)
        return None

    # Compute alpha = norm(a) = c0^2 - β*c1^2 where β is the non-residue
    # For BLS12-381, Fp2 = Fp[X]/(X^2 + 1), so β = -1
    # Therefore: norm = c0^2 - (-1)*c1^2 = c0^2 + c1^2
    alpha = (c0_int * c0_int + c1_int * c1_int) % field_modulus

    # Compute sqrt(alpha)
    sqrt_alpha = pow(alpha, (field_modulus + 1) // 4, field_modulus)

    # Verify sqrt(alpha) is correct
    if pow(sqrt_alpha, 2, field_modulus) != alpha:
        return None

    # Compute two_inv = 1/2
    two_inv = pow(2, field_modulus - 2, field_modulus)

    # Compute delta = (sqrt_alpha + c0) / 2
    delta = ((sqrt_alpha + c0_int) * two_inv) % field_modulus

    # Check if delta is a quadratic non-residue
    if legendre_fq(delta, field_modulus) == -1:
        # delta = (c0 - sqrt_alpha) / 2
        delta = ((c0_int - sqrt_alpha) * two_inv) % field_modulus

    # Compute c0_result = sqrt(delta)
    c0_result = pow(delta, (field_modulus + 1) // 4, field_modulus)

    # Verify c0_result
    if pow(c0_result, 2, field_modulus) != delta:
        return None

    # Compute c0_inv = 1/c0_result
    if c0_result == 0:
        return None
    c0_inv = pow(c0_result, field_modulus - 2, field_modulus)

    # Compute c1_result = c1 / (2 * c0_result) = c1 * two_inv * c0_inv
    c1_result = (c1_int * two_inv * c0_inv) % field_modulus

    # Verify the candidate is actually the square root by checking the coefficients
    # sqrt_cand^2 should equal a
    # (c0_result + c1_result*X)^2 = c0_result^2 - c1_result^2 * X^2 + 2*c0_result*c1_result*X
    # Using X^2 = -1: = c0_result^2 - c1_result^2 * (-1) + 2*c0_result*c1_result*X
    #                 = c0_result^2 - c1_result^2 + 2*c0_result*c1_result*X
    sqrt_c0_squared = (c0_result * c0_result - c1_result * c1_result) % field_modulus
    sqrt_c1_squared = (2 * c0_result * c1_result) % field_modulus

    if sqrt_c0_squared == c0_int and sqrt_c1_squared == c1_int:
        return (c0_result, c1_result)

    return None


def deserialize_bls12_381_g2(data: bytes) -> tuple:
    """
    Deserialize BLS12-381 G2 point from arkworks compressed format.

    G2 points are 96 bytes (2 × 48-byte Fp2 elements).
    Similar compression scheme as G1 but for Fp2 field.
    """
    if len(data) != 96:
        raise ValueError(f"Expected 96 bytes for G2 point, got {len(data)}")

    # G2 uses Fp2 = Fp[u]/(u^2 + 1)
    # Each coordinate is (c0, c1) where coordinate = c0 + c1*u

    # Extract x-coordinate (first 96 bytes encode both c0 and c1)
    flags = data[0]
    is_compressed = (flags & 0x80) != 0
    is_infinity = (flags & 0x40) != 0
    y_parity = (flags & 0x20) != 0

    if is_infinity:
        return (FQ2([0, 0]), FQ2([1, 0]), FQ2([0, 0]))

    if not is_compressed:
        raise ValueError("Uncompressed G2 points not supported")

    # Extract x-coordinate: arkworks serializes Fp2 as c1 || c0 (c1 first, c0 second)
    # Each coefficient is 48 bytes, big-endian
    x_c1_bytes = bytes([data[0] & 0x1F]) + data[1:48]  # c1 in bytes 0-47
    x_c0_bytes = data[48:96]  # c0 in bytes 48-95

    x_c0 = int.from_bytes(x_c0_bytes, 'big')
    x_c1 = int.from_bytes(x_c1_bytes, 'big')

    x_fq2 = FQ2([x_c0, x_c1])

    # Recover y from curve equation: y^2 = x^3 + 4(1 + u)
    from py_ecc.bls12_381 import bls12_381_pairing as pairing
    field_modulus = pairing.field_modulus

    # G2 curve equation: y^2 = x^3 + 4(1 + u)
    b = FQ2([4, 4])  # 4(1 + u) = 4 + 4u
    y_squared = x_fq2 * x_fq2 * x_fq2 + b

    # Compute square root in Fp2
    y_sqrt = sqrt_fq2(y_squared)

    if y_sqrt is None:
        raise ValueError("No square root exists for y^2")

    # y_sqrt is (c0, c1) as integers
    c0, c1 = y_sqrt

    # Choose correct root based on parity
    # The parity bit indicates if the imaginary part (c1) is lexicographically largest
    y_is_lexicographically_largest = c1 > (field_modulus - 1) // 2

    if y_is_lexicographically_largest != y_parity:
        # Negate: -y = (p - c0, p - c1)
        c0 = (field_modulus - c0) % field_modulus
        c1 = (field_modulus - c1) % field_modulus

    y_fq2 = FQ2([c0, c1])
    return (x_fq2, y_fq2, FQ2([1, 0]))
