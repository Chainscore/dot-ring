"""VRF transcript primitives from Bandersnatch VRF spec sections 1.5-1.9.

The public helpers intentionally keep spec names: `vrf_transcript`, `nonce`,
`challenge`, and `point_to_hash`.
"""

from __future__ import annotations

from typing import Any

from dot_ring.curve.curve import CurveVariant
from dot_ring.curve.point import CurvePoint
from dot_ring.vrf.domain import DomSep
from dot_ring.vrf.io import VrfIo

SECURITY_PARAMETER = 128
CHALLENGE_LEN = SECURITY_PARAMETER // 8


class VrfTranscript:
    """Append-only transcript with counter-mode XOF squeezing; no absorb after squeeze."""

    def __init__(self, label: bytes, hash_fn: Any) -> None:
        self._hash_fn = hash_fn
        self._absorbed = bytearray(label)
        self._seed: bytes | None = None
        self._squeeze_offset = 0

    def copy(self) -> VrfTranscript:
        other = VrfTranscript(b"", self._hash_fn)
        other._absorbed = bytearray(self._absorbed)
        other._seed = self._seed
        other._squeeze_offset = self._squeeze_offset
        return other

    def absorb(self, data: bytes) -> None:
        if self._seed is not None:
            raise ValueError("cannot absorb after squeeze")
        self._absorbed.extend(data)

    def squeeze(self, size: int) -> bytes:
        if self._seed is None:
            self._seed = bytes(self._absorbed)
        start = self._squeeze_offset
        end = start + size
        stream = squeeze_transcript_bytes(self._hash_fn, self._seed, end)
        self._squeeze_offset = end
        return stream[start:end]


def suite_id(curve: CurveVariant) -> bytes:
    return curve.curve.params.suite_id


def scalar_len(curve: CurveVariant) -> int:
    return (curve.curve.params.subgroup_order.bit_length() + 7) // 8


def point_len(curve: CurveVariant) -> int:
    encoding = curve.curve.params.encoding
    return encoding.point_len * (2 if encoding.uncompressed else 1)


def scalar_encode(curve: CurveVariant, value: int) -> bytes:
    return int(value % curve.curve.params.subgroup_order).to_bytes(scalar_len(curve), "little")


def scalar_decode(curve: CurveVariant, value: bytes) -> int:
    return int.from_bytes(value, "little")


def _expanded_scalar_len(curve: CurveVariant, sec_bits: int = SECURITY_PARAMETER) -> int:
    return (curve.curve.params.subgroup_order.bit_length() + sec_bits + 7) // 8


def _transcript_for(curve: CurveVariant) -> VrfTranscript:
    return VrfTranscript(suite_id(curve), curve.curve.params.hash_fn)


def _nonce_scalar(curve: CurveVariant, transcript: VrfTranscript) -> int:
    return int.from_bytes(transcript.squeeze(_expanded_scalar_len(curve)), "little") % curve.curve.params.subgroup_order


def _challenge_scalar(curve: CurveVariant, transcript: VrfTranscript) -> int:
    return int.from_bytes(transcript.squeeze(CHALLENGE_LEN), "little") % curve.curve.params.subgroup_order


def nonce(curve: CurveVariant, secret_scalar: int, transcript: VrfTranscript | None = None) -> int:
    """Spec section 1.8: derive the nonce from `NonceExpand` then `Nonce`; abort on zero."""
    t = transcript.copy() if transcript is not None else _transcript_for(curve)

    t_exp = t.copy()
    t_exp.absorb(bytes([DomSep.NONCE_EXPAND]))
    t_exp.absorb(scalar_encode(curve, secret_scalar))
    secret_hash = t_exp.squeeze(64)

    t.absorb(bytes([DomSep.NONCE]))
    t.absorb(secret_hash)
    nonce_scalar = _nonce_scalar(curve, t)
    if nonce_scalar == 0:
        raise ValueError("nonce scalar is zero")
    return nonce_scalar


def challenge(curve: CurveVariant, points: list[CurvePoint], transcript: VrfTranscript | None = None) -> int:
    """Spec section 1.9: absorb `Challenge` and encoded points, then squeeze challenge_len."""
    t = transcript.copy() if transcript is not None else _transcript_for(curve)
    t.absorb(bytes([DomSep.CHALLENGE]))
    for point in points:
        t.absorb(point.point_to_string())
    return _challenge_scalar(curve, t)


def point_to_hash(curve: CurveVariant, point: CurvePoint, size: int = 32) -> bytes:
    """Spec section 1.4: domain-separate `O` before producing the user-visible VRF hash."""
    t = _transcript_for(curve)
    t.absorb(bytes([DomSep.POINT_TO_HASH]))
    t.absorb(point.point_to_string())
    return t.squeeze(size)


def vrf_transcript(
    curve: CurveVariant,
    scheme: DomSep,
    ios: list[VrfIo],
    ad: bytes,
) -> tuple[VrfTranscript, VrfIo]:
    """Spec section 1.7: bind scheme/I/O/AD and return the delinearized merged pair."""
    t, zs = vrf_transcript_scalars(curve, scheme, ios, ad)
    if not ios:
        zero = curve.identity()
        return t, VrfIo(zero, zero)
    if len(ios) == 1:
        return t, ios[0]

    input_acc = curve.msm([io.input for io in ios], zs)
    output_acc = curve.msm([io.output for io in ios], zs)
    return t, VrfIo(input_acc, output_acc)


def vrf_transcript_scalars(
    curve: CurveVariant,
    scheme: DomSep,
    ios: list[VrfIo],
    ad: bytes,
) -> tuple[VrfTranscript, list[int]]:
    """Spec section 1.7 plus section 1.6 delinearization scalars for these I/O pairs."""
    t = _transcript_for(curve)
    t.absorb(bytes([scheme]))
    t.absorb(len(ios).to_bytes(8, "little"))
    for io in ios:
        t.absorb(io.encode())
    t.absorb(len(ad).to_bytes(8, "little"))
    t.absorb(ad)
    return t, delinearization_scalars(curve, t, len(ios))


def delinearization_scalars(curve: CurveVariant, transcript: VrfTranscript, count: int) -> list[int]:
    """Spec section 1.6: fork, absorb `Delinearize`, return `z_0 = 1` then squeezed scalars."""
    if count <= 0:
        return []

    t = transcript.copy()
    t.absorb(bytes([DomSep.DELINEARIZE]))
    order = curve.curve.params.subgroup_order
    scalars = [1]
    for _ in range(count - 1):
        scalars.append(int.from_bytes(t.squeeze(CHALLENGE_LEN), "little") % order)
    return scalars


def schnorr_ios(curve: CurveVariant, public_key: CurvePoint, ios: list[VrfIo]) -> list[VrfIo]:
    generator = curve.generator_point()
    return [VrfIo(generator, public_key), *ios]


def secret_from_seed_scalar(curve: CurveVariant, seed: bytes) -> int:
    if len(seed) != 32:
        raise ValueError("seed must be exactly 32 bytes")
    base_secret = int.from_bytes(seed, "little") % curve.curve.params.subgroup_order
    counter = 0
    while True:
        t = _transcript_for(curve)
        t.absorb(seed)
        if counter:
            t.absorb(bytes([counter]))
        secret = nonce(curve, base_secret, t)
        if secret != 0:
            return secret
        counter += 1
        if counter > 255:
            raise RuntimeError("failed to derive non-zero secret scalar")


def squeeze_transcript_bytes(hash_fn: Any, absorbed: bytes, size: int) -> bytes:
    hasher = hash_fn()
    if hasher.name in {"shake_128", "shake_256"}:
        hasher.update(absorbed)
        return hasher.digest(size)

    seed = hash_fn(absorbed).digest()
    block_size = len(seed)
    block_count = (size + block_size - 1) // block_size
    return b"".join(hash_fn(seed + counter.to_bytes(8, "little")).digest() for counter in range(block_count))[:size]


def hash_to_curve_tai(point_type: Any, data: bytes, curve: Any) -> CurvePoint:
    field_len = (curve.params.field_modulus.bit_length() + 7) // 8

    prefix = VrfTranscript(curve.params.suite_id, curve.params.hash_fn)
    prefix.absorb(bytes([DomSep.HASH_TO_CURVE]))
    prefix.absorb(len(data).to_bytes(8, "little"))
    prefix.absorb(data)

    for counter in range(256):
        t = prefix.copy()
        t.absorb(bytes([counter]))
        candidate = bytearray(t.squeeze(field_len))
        if hasattr(curve.params, "a") and hasattr(curve.params, "b"):
            shave = field_len * 8 - curve.params.field_modulus.bit_length()
            if shave:
                candidate[-1] &= (1 << (8 - shave)) - 1
            candidate = bytearray(candidate + b"\x80")
        else:
            sign = candidate[-1] & 0x80
            shave = field_len * 8 - curve.params.field_modulus.bit_length()
            if shave:
                candidate[-1] &= (1 << (8 - shave)) - 1
            candidate[-1] |= sign
        try:
            point = point_type.string_to_point(bytes(candidate), curve)
        except ValueError:
            continue
        if point.curve.params.cofactor > 1:
            point = point * point.curve.params.cofactor
        if not point.is_identity():
            return point
    raise ValueError("hash_to_curve_tai failed")
