from pyblst import BlstP1Element, BlstP2Element
import blst 

def _ensure_bytes(data, expected_len, label):
    raw = bytes(data)
    if len(raw) != expected_len:
        raise ValueError(f"{label} serialization must be {expected_len} bytes, got {len(raw)}")
    return raw


def _ensure_blst_p1_affine(point):
    if isinstance(point, blst.P1_Affine):
        return point
    if isinstance(point, blst.P1):
        return point.to_affine()
    if isinstance(point, BlstP1Element):
        comp = _ensure_bytes(point.compress(), 48, "G1")
        return blst.P1_Affine(comp)
    raise TypeError("Unsupported G1 point type for blst pairing")


def _ensure_blst_p2_affine(point):
    if isinstance(point, blst.P2_Affine):
        return point
    if isinstance(point, blst.P2):
        return point.to_affine()
    if isinstance(point, BlstP2Element):
        comp = _ensure_bytes(point.compress(), 96, "G2")
        return blst.P2_Affine(comp)
    raise TypeError("Unsupported G2 point type for blst pairing")


def blst_miller_loop(p1, p2):
    return blst.PT(_ensure_blst_p2_affine(p2), _ensure_blst_p1_affine(p1))


def blst_final_verify(lhs, rhs):
    return blst.PT.finalverify(lhs, rhs)