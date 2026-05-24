from __future__ import annotations

from dot_ring.curve.curve import CurveVariant
from dot_ring.curve.specs.bandersnatch import Bandersnatch
from dot_ring.vrf.ietf import TinyVRF
from dot_ring.vrf.transcript import scalar_encode, secret_from_seed_scalar


def secret_from_seed(seed: bytes, curve: CurveVariant = Bandersnatch) -> tuple[bytes, bytes]:
    """
    Deterministically derive a secret scalar and public key from a seed.

    Returns:
        (public_key_bytes, secret_scalar_bytes)
    """
    if not isinstance(seed, (bytes, bytearray)):
        raise TypeError("seed must be bytes")
    if not isinstance(curve, CurveVariant):
        raise TypeError("curve must be a CurveVariant")

    sk_int = secret_from_seed_scalar(curve, bytes(seed))
    sk_bytes = scalar_encode(curve, sk_int)
    pk_bytes = TinyVRF[curve].get_public_key(sk_bytes)
    return pk_bytes, sk_bytes
