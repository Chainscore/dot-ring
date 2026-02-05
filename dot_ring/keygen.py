from __future__ import annotations

from typing import Literal, cast

from dot_ring.curve.curve import CurveVariant
from dot_ring.curve.specs.bandersnatch import Bandersnatch
from dot_ring.ring_proof.helpers import Helpers
from dot_ring.vrf.ietf.ietf import IETF_VRF


def _hash_seed(curve: CurveVariant, seed: bytes, counter: int) -> bytes:
    hasher = curve.curve.H_A()
    hasher.update(seed)
    if counter:
        hasher.update(bytes([counter]))
    if curve.curve._uses_xof():
        length = curve.curve._default_xof_len()
        return cast(bytes, hasher.digest(length))
    return cast(bytes, hasher.digest())


def secret_from_seed(seed: bytes, curve: CurveVariant = Bandersnatch) -> tuple[bytes, bytes]:
    """
    Deterministically derive a secret scalar and public key from a seed.

    Mirrors ark-vrf's Secret::from_seed:
    - Hash seed with curve's hash function
    - Interpret hash output as little-endian integer, reduce modulo curve order
    - If zero, append a counter byte and rehash

    Returns:
        (public_key_bytes, secret_scalar_bytes)
    """
    if not isinstance(seed, (bytes, bytearray)):
        raise TypeError("seed must be bytes")
    if not isinstance(curve, CurveVariant):
        raise TypeError("curve must be a CurveVariant")

    seed_bytes = bytes(seed)
    order = curve.curve.ORDER
    scalar_len = (order.bit_length() + 7) // 8

    counter = 0
    while True:
        digest = _hash_seed(curve, seed_bytes, counter)
        sk_int = int.from_bytes(digest, "little") % order
        if sk_int != 0:
            break
        counter = (counter + 1) & 0xFF
        if counter == 0:
            raise RuntimeError("failed to derive non-zero secret scalar")

    sk_bytes = Helpers.int_to_str(
        sk_int,
        cast(Literal["little", "big"], curve.curve.ENDIAN),
        scalar_len,
    )
    pk_bytes = IETF_VRF[curve].get_public_key(sk_bytes)
    return pk_bytes, sk_bytes
