"""Bandersnatch VRF spec section 1.6 procedures."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from dot_ring.curve.curve import CurveVariant
from dot_ring.curve.point import CurvePoint
from dot_ring.vrf.codec import dec_scalar_mod, enc_64, enc_point, enc_scalar
from dot_ring.vrf.domain import DomSep

SECURITY_PARAMETER = 128
CHALLENGE_LEN = SECURITY_PARAMETER // 8


@dataclass(frozen=True)
class VrfIo:
    input: CurvePoint
    output: CurvePoint

    def encode(self) -> bytes:
        return enc_point(self.input) + enc_point(self.output)


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


def new_transcript(curve: CurveVariant) -> VrfTranscript:
    return VrfTranscript(curve.curve.params.suite_id, curve.curve.params.hash_fn)


def _expanded_scalar_len(curve: CurveVariant, sec_bits: int = SECURITY_PARAMETER) -> int:
    return (curve.curve.params.subgroup_order.bit_length() + sec_bits + 7) // 8


def nonce(curve: CurveVariant, secret_scalar: int, transcript: VrfTranscript | None = None) -> int:
    """Spec section 1.6.6: derive the nonce from `NonceExpand` then `Nonce`."""
    t = transcript.copy() if transcript is not None else new_transcript(curve)

    t_exp = t.copy()
    t_exp.absorb(bytes([DomSep.NONCE_EXPAND]))
    t_exp.absorb(enc_scalar(curve, secret_scalar))
    secret_hash = t_exp.squeeze(64)

    t.absorb(bytes([DomSep.NONCE]))
    t.absorb(secret_hash)
    nonce_scalar = dec_scalar_mod(curve, t.squeeze(_expanded_scalar_len(curve)))
    if nonce_scalar == 0:
        raise ValueError("nonce scalar is zero")
    return nonce_scalar


def challenge(curve: CurveVariant, points: list[CurvePoint], transcript: VrfTranscript | None = None) -> int:
    """Spec section 1.6.7: absorb `Challenge` and encoded points, then squeeze a scalar."""
    t = transcript.copy() if transcript is not None else new_transcript(curve)
    t.absorb(bytes([DomSep.CHALLENGE]))
    for point in points:
        t.absorb(enc_point(point))
    return dec_scalar_mod(curve, t.squeeze(CHALLENGE_LEN))


def point_to_hash(curve: CurveVariant, point: CurvePoint, size: int = 32) -> bytes:
    """Spec section 1.6.3: derive the user-visible VRF hash from output point `O`."""
    t = new_transcript(curve)
    t.absorb(bytes([DomSep.POINT_TO_HASH]))
    t.absorb(enc_point(point))
    return t.squeeze(size)


def vrf_transcript(
    curve: CurveVariant,
    scheme: DomSep,
    ios: list[VrfIo],
    ad: bytes,
) -> tuple[VrfTranscript, VrfIo]:
    """Spec section 1.6.5: bind scheme/I/O/AD and return the delinearized pair."""
    t, zs = vrf_transcript_scalars(curve, scheme, ios, ad)
    if not ios:
        zero = curve.point_type.identity()
        return t, VrfIo(zero, zero)
    if len(ios) == 1:
        return t, ios[0]

    input_acc = curve.point_type.msm([io.input for io in ios], zs)
    output_acc = curve.point_type.msm([io.output for io in ios], zs)
    return t, VrfIo(input_acc, output_acc)


def vrf_transcript_scalars(
    curve: CurveVariant,
    scheme: DomSep,
    ios: list[VrfIo],
    ad: bytes,
) -> tuple[VrfTranscript, list[int]]:
    t = new_transcript(curve)
    t.absorb(bytes([scheme]))
    t.absorb(enc_64(len(ios)))
    for io in ios:
        t.absorb(io.encode())
    t.absorb(enc_64(len(ad)))
    t.absorb(ad)
    return t, delinearization_scalars(curve, t, len(ios))


def delinearization_scalars(curve: CurveVariant, transcript: VrfTranscript, count: int) -> list[int]:
    """Spec section 1.6.4: fork, absorb `Delinearize`, return `z_0 = 1` then squeezed scalars."""
    if count <= 0:
        return []

    t = transcript.copy()
    t.absorb(bytes([DomSep.DELINEARIZE]))
    scalars = [1]
    for _ in range(count - 1):
        scalars.append(dec_scalar_mod(curve, t.squeeze(CHALLENGE_LEN)))
    return scalars


def secret_from_seed_scalar(curve: CurveVariant, seed: bytes) -> int:
    if len(seed) != 32:
        raise ValueError("seed must be exactly 32 bytes")
    base_secret = dec_scalar_mod(curve, seed)
    counter = 0
    while True:
        t = new_transcript(curve)
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
