
import time
from typing import List, Tuple
import py_ecc.optimized_bls12_381 as bls
from py_ecc.bls import point_compression
from dot_ring import blst
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


def g1_to_blst(p) -> blst.P1:
    """Convert py_ecc G1 point (Jacobian tuple) to blst.P1"""
    compressed_int = point_compression.compress_G1(p)
    compressed_bytes = compressed_int.to_bytes(48, "big")
    return blst.P1(blst.P1_Affine(compressed_bytes))


def g2_to_blst(p) -> blst.P2:
    """Convert py_ecc G2 point to blst.P2"""
    z1, z2 = point_compression.compress_G2(p)
    b1 = z1.to_bytes(48, "big")
    b2 = z2.to_bytes(48, "big")
    return blst.P2(blst.P2_Affine(b1 + b2))


def blst_p1_to_fq_tuple(blst_point: blst.P1) -> Tuple[FQ, FQ, FQ]:
    """Convert blst.P1 point back to (FQ, FQ, FQ) tuple in Jacobian coordinates"""
    point_bytes = blst_point.serialize()
    x_bytes = point_bytes[:48]
    y_bytes = point_bytes[48:96]
    x_int = int.from_bytes(x_bytes, "big")
    y_int = int.from_bytes(y_bytes, "big")
    return (FQ(x_int), FQ(y_int), FQ(1))

