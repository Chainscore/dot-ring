from typing import cast

from dot_ring import blst


def _ensure_blst_p1_affine(point: blst.P1 | blst.P1_Affine) -> blst.P1_Affine:
    """Convert point to blst.P1_Affine for pairing."""
    if isinstance(point, blst.P1_Affine):
        return point
    if isinstance(point, blst.P1):
        return cast(blst.P1_Affine, point.to_affine())
    raise TypeError(f"Unsupported G1 point type: {type(point)}")


def _ensure_blst_p2_affine(point: blst.P2 | blst.P2_Affine) -> blst.P2_Affine:
    """Convert point to blst.P2_Affine for pairing."""
    if isinstance(point, blst.P2_Affine):
        return point
    if isinstance(point, blst.P2):
        return cast(blst.P2_Affine, point.to_affine())
    raise TypeError(f"Unsupported G2 point type: {type(point)}")


def blst_miller_loop(
    p1: blst.P1 | blst.P1_Affine, p2: blst.P2 | blst.P2_Affine
) -> blst.PT:
    """Compute Miller loop for pairing."""
    return blst.PT(_ensure_blst_p2_affine(p2), _ensure_blst_p1_affine(p1))


def blst_final_verify(lhs: blst.PT, rhs: blst.PT) -> bool:
    """Final verification step for pairing equality check."""
    return cast(bool, blst.PT.finalverify(lhs, rhs))
