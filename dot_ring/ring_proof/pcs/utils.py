
from typing import List
import py_ecc.optimized_bls12_381 as bls
from pyblst import BlstP1Element, BlstP2Element
from py_ecc.bls import point_compression
import blst
from py_ecc.optimized_bls12_381 import FQ

Scalar = int
CoeffVector = List[Scalar]


def synthetic_div(poly: CoeffVector, x: Scalar, y: Scalar) -> CoeffVector:
    """Return q(X) such that f(X)−y = (X−x)·q(X).  Checks remainder."""
    n = len(poly)
    q = [0] * (n - 1)
    rem = poly[-1]
    for i in range(n - 2, -1, -1):
        q[i] = rem
        rem = (rem * x + poly[i]) % bls.curve_order
    if rem != y:
        raise ValueError("point/value pair inconsistent with polynomial")
    return q


# convert py_ecc's bls g1 type point to blst_P1
def py_ecc_point_to_blst(p):
    compressed_int = point_compression.compress_G1(p)
    compressed_bytes = compressed_int.to_bytes(48, "big")
    return BlstP1Element().uncompress(compressed_bytes)


# convert py_ecc's bls g2 type point to blst_P2
def py_ecc_g2_point_to_blst(p):
    z1, z2 = point_compression.compress_G2(p)
    # Convert to bytes (48 bytes each, big endian)
    b1 = z1.to_bytes(48, "big")
    b2 = z2.to_bytes(48, "big")
    return BlstP2Element().uncompress(b1 + b2)


def convert_g1_point_to_blst(g1_tuple):
    """Convert (x, y, z) tuple to blst.P1 point"""
    x, y, z = g1_tuple

    # Convert to affine coordinates
    x_affine, y_affine = jacobian_to_affine_coords(x, y, z)

    if x_affine is None:
        # Point at infinity
        return blst.P1()  # Identity point

    # Convert to bytes (48 bytes each for x and y)
    x_bytes = x_affine.to_bytes(48, "big")
    y_bytes = y_affine.to_bytes(48, "big")

    # Create affine point from 96 bytes (48 + 48)
    point_bytes = x_bytes + y_bytes

    try:
        # Method 1: Try direct P1_Affine constructor
        affine_point = blst.P1_Affine(point_bytes)
        return blst.P1(affine_point)
    except:
        raise ValueError("All conversion methods failed")


def jacobian_to_affine_coords(x, y, z):
    """Convert Jacobian coordinates (x, y, z) to affine (x/z², y/z³)"""
    # BLS12-381 field prime
    p = 0x1A0111EA397FE69A4B1BA7B6434BACD764774B84F38512BF6730D2A0F6B0F6241EABFFFEB153FFFFB9FEFFFFFFFFAAAB

    if int(z) == 0:
        # Point at infinity
        return None, None
    elif int(z) == 1:
        # Already in affine coordinates
        return int(x), int(y)
    else:
        # Convert z to int and compute modular inverse
        z_int = int(z)
        z_inv = pow(z_int, -1, p)  # Modular inverse
        z_inv_squared = (z_inv * z_inv) % p
        z_inv_cubed = (z_inv_squared * z_inv) % p

        x_affine = (int(x) * z_inv_squared) % p
        y_affine = (int(y) * z_inv_cubed) % p

        return x_affine, y_affine
        

def blst_p1_to_fq_tuple(blst_point):
    """Convert blst.P1 point back to (FQ, FQ, FQ) tuple in Jacobian coordinates"""
    
    if isinstance(blst_point, tuple):
        return blst_point

    try:
        # Method 1: Convert to affine coordinates first
        affine_point = blst_point.to_affine()

        # Serialize the affine point to bytes (96 bytes: 48 for x, 48 for y)
        point_bytes = affine_point.serialize()

        # Split into x and y coordinates (48 bytes each)
        x_bytes = point_bytes[:48]
        y_bytes = point_bytes[48:96]

        # Convert bytes back to integers
        x_int = int.from_bytes(x_bytes, "big")
        y_int = int.from_bytes(y_bytes, "big")

        # Create FQ elements from integers
        x_fq = FQ(x_int)
        y_fq = FQ(y_int)
        z_fq = FQ(1)  # Affine coordinates have z=1

        return (x_fq, y_fq, z_fq)

    except Exception as e:
        raise ValueError(f"Conversion method failed: {e}")
