import py_ecc.optimized_bls12_381 as bls
from py_ecc.bls import point_compression

from dot_ring import blst

Scalar = int
CoeffVector = list[Scalar]


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


def g1_to_blst(p: tuple | blst.P1 | blst.P1_Affine) -> blst.P1:
    """Convert a G1 point to blst.P1."""
    if isinstance(p, blst.P1):
        return p
    if isinstance(p, blst.P1_Affine):
        return blst.P1(p)
    compressed_int = point_compression.compress_G1(p)
    compressed_bytes = compressed_int.to_bytes(48, "big")
    return blst.P1(blst.P1_Affine(compressed_bytes))


def g2_to_blst(p: tuple | blst.P2 | blst.P2_Affine) -> blst.P2:
    """Convert a G2 point to blst.P2."""
    if isinstance(p, blst.P2):
        return p
    if isinstance(p, blst.P2_Affine):
        return blst.P2(p)
    z1, z2 = point_compression.compress_G2(p)
    b1 = z1.to_bytes(48, "big")
    b2 = z2.to_bytes(48, "big")
    return blst.P2(blst.P2_Affine(b1 + b2))
