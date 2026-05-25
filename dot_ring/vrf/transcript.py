from __future__ import annotations

from typing import Any, cast

from dot_ring.curve.curve import CurveVariant
from dot_ring.curve.point import CurvePoint
from dot_ring.vrf.delinearize import DelinearizeScalars
from dot_ring.vrf.domain import DomSep
from dot_ring.vrf.spec_transcript import SpecTranscript
from dot_ring.vrf.transcript_constants import CHALLENGE_LEN, SECURITY_PARAMETER
from dot_ring.vrf.vrf_io import VrfIo


def suite_id(curve: CurveVariant) -> bytes:
    return cast(bytes, curve.curve.SUITE_ID or curve.curve.SUITE_STRING)


def scalar_len(curve: CurveVariant) -> int:
    return (cast(int, curve.curve.ORDER).bit_length() + 7) // 8


def scalar_encode(curve: CurveVariant, value: int) -> bytes:
    return int(value % curve.curve.ORDER).to_bytes(scalar_len(curve), "little")


def scalar_decode(curve: CurveVariant, value: bytes) -> int:
    return int.from_bytes(value, "little")


def expanded_scalar_len(curve: CurveVariant, sec_bits: int = SECURITY_PARAMETER) -> int:
    return (cast(int, curve.curve.ORDER).bit_length() + sec_bits + 7) // 8


def transcript_for(curve: CurveVariant) -> SpecTranscript:
    return SpecTranscript(suite_id(curve), curve.curve.TRANSCRIPT_HASH)


def nonce_scalar(curve: CurveVariant, transcript: SpecTranscript) -> int:
    return int.from_bytes(transcript.squeeze_raw(expanded_scalar_len(curve)), "little") % cast(int, curve.curve.ORDER)


def challenge_scalar(curve: CurveVariant, transcript: SpecTranscript) -> int:
    return int.from_bytes(transcript.squeeze_raw(CHALLENGE_LEN), "little") % cast(int, curve.curve.ORDER)


def nonce(curve: CurveVariant, secret_scalar: int, transcript: SpecTranscript | None = None) -> int:
    t = transcript.clone() if transcript is not None else transcript_for(curve)

    t_exp = t.clone()
    t_exp.absorb_raw(bytes([DomSep.NONCE_EXPAND]))
    t_exp.absorb_scalar(curve, secret_scalar)
    secret_hash = t_exp.squeeze_raw(64)

    t.absorb_raw(bytes([DomSep.NONCE]))
    t.absorb_raw(secret_hash)
    return nonce_scalar(curve, t)


def challenge(curve: CurveVariant, points: list[CurvePoint], transcript: SpecTranscript | None = None) -> int:
    t = transcript.clone() if transcript is not None else transcript_for(curve)
    t.absorb_raw(bytes([DomSep.CHALLENGE]))
    for point in points:
        t.absorb_point(point)
    return challenge_scalar(curve, t)


def point_to_hash(curve: CurveVariant, point: CurvePoint, size: int = 32) -> bytes:
    t = transcript_for(curve)
    t.absorb_raw(bytes([DomSep.POINT_TO_HASH]))
    t.absorb_point(point)
    return t.squeeze_raw(size)


def vrf_transcript(
    curve: CurveVariant,
    scheme: DomSep,
    ios: list[VrfIo],
    ad: bytes,
) -> tuple[SpecTranscript, VrfIo]:
    t, scalars = vrf_transcript_scalars(curve, scheme, ios, ad)
    if not ios:
        zero = curve.point.identity()
        return t, VrfIo(zero, zero)
    if len(ios) == 1:
        return t, ios[0]

    input_acc = curve.point.identity()
    output_acc = curve.point.identity()
    for io in ios:
        z = scalars.next()
        input_acc = input_acc + io.input * z
        output_acc = output_acc + io.output * z
    return t, VrfIo(input_acc, output_acc)


def vrf_transcript_scalars(
    curve: CurveVariant,
    scheme: DomSep,
    ios: list[VrfIo],
    ad: bytes,
) -> tuple[SpecTranscript, DelinearizeScalars]:
    t = transcript_for(curve)
    t.absorb_raw(bytes([scheme]))
    t.absorb_raw(len(ios).to_bytes(8, "little"))
    for io in ios:
        t.absorb_raw(io.to_bytes())
    t.absorb_raw(len(ad).to_bytes(8, "little"))
    t.absorb_raw(ad)
    return t, DelinearizeScalars(curve, t)


def schnorr_ios(curve: CurveVariant, public_key: CurvePoint, ios: list[VrfIo]) -> list[VrfIo]:
    generator = curve.point.generator_point()
    return [VrfIo(generator, public_key), *ios]


def secret_from_seed_scalar(curve: CurveVariant, seed: bytes) -> int:
    if len(seed) != 32:
        raise ValueError("seed must be exactly 32 bytes")
    base_secret = int.from_bytes(seed, "little") % curve.curve.ORDER
    counter = 0
    while True:
        t = transcript_for(curve)
        t.absorb_raw(seed)
        if counter:
            t.absorb_raw(bytes([counter]))
        secret = nonce(curve, base_secret, t)
        if secret != 0:
            return secret
        counter += 1
        if counter > 255:
            raise RuntimeError("failed to derive non-zero secret scalar")


def hash_to_curve_tai(point_cls: Any, data: bytes) -> CurvePoint:
    curve = point_cls.curve
    field_len = (curve.PRIME_FIELD.bit_length() + 7) // 8

    prefix = SpecTranscript(curve.SUITE_ID or curve.SUITE_STRING, curve.TRANSCRIPT_HASH)
    prefix.absorb_raw(bytes([DomSep.HASH_TO_CURVE]))
    prefix.absorb_raw(len(data).to_bytes(8, "little"))
    prefix.absorb_raw(data)

    for counter in range(256):
        t = prefix.clone()
        t.absorb_raw(bytes([counter]))
        candidate = bytearray(t.squeeze_raw(field_len))
        if hasattr(curve, "WeierstrassA"):
            shave = field_len * 8 - curve.PRIME_FIELD.bit_length()
            if shave:
                candidate[-1] &= (1 << (8 - shave)) - 1
            candidate = bytearray(candidate + b"\x80")
        else:
            sign = candidate[-1] & 0x80
            shave = field_len * 8 - curve.PRIME_FIELD.bit_length()
            if shave:
                candidate[-1] &= (1 << (8 - shave)) - 1
            candidate[-1] |= sign
        try:
            point = point_cls.string_to_point(bytes(candidate))
        except ValueError:
            continue
        if point.curve.COFACTOR > 1:
            point = point * point.curve.COFACTOR
        if not point.is_identity():
            return point
    raise ValueError("hash_to_curve_tai failed")
