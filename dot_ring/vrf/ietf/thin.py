from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Any

from dot_ring.curve.curve import CurveVariant
from dot_ring.curve.point import CurvePoint
from dot_ring.vrf.transcript import (
    DomSep,
    VrfIo,
    challenge,
    nonce,
    point_len,
    point_to_hash,
    scalar_decode,
    scalar_encode,
    scalar_len,
    schnorr_ios,
    vrf_transcript,
    vrf_transcript_scalars,
)

from ..vrf import VRF


@dataclass
class ThinBatchItem:
    c: int
    ios: list[VrfIo]
    zs: list[int]
    r: CurvePoint
    s: int


@dataclass
class ThinVRF(VRF[Any]):
    """Batch-friendly VRF-AD proof storing the nonce commitment."""

    output_point: CurvePoint
    r: CurvePoint
    s: int

    @classmethod
    def decode(cls, proof_bytes: bytes) -> ThinVRF:
        encoded_point_len = point_len(cls.cv)
        scalar_size = scalar_len(cls.cv)
        expected = 2 * encoded_point_len + scalar_size
        if len(proof_bytes) != expected:
            raise ValueError(f"invalid Thin VRF proof length: expected {expected}, got {len(proof_bytes)}")
        try:
            output_point = cls.cv.string_to_point(proof_bytes[:encoded_point_len])
            r = cls.cv.string_to_point(proof_bytes[encoded_point_len : 2 * encoded_point_len])
        except ValueError as exc:
            raise ValueError("Invalid point in proof") from exc
        s = scalar_decode(cls.cv, proof_bytes[2 * encoded_point_len :])
        if s >= cls.cv.curve.params.subgroup_order:
            raise ValueError("Response scalar s is not less than the curve order")
        return cls(output_point, r, s)

    def encode(self) -> bytes:
        return self.output_point.point_to_string() + self.r.point_to_string() + scalar_encode(self.cv, self.s)

    @classmethod
    def prove(
        cls,
        alpha: bytes,
        secret_key: bytes,
        additional_data: bytes,
        salt: bytes = b"",
    ) -> ThinVRF:
        secret_scalar = scalar_decode(cls.cv, secret_key)
        public_key = cls.cv.generator_point() * secret_scalar
        input_point = cls.cv.encode_to_curve(alpha, salt)
        output_point = input_point * secret_scalar
        return cls.prove_ios([VrfIo(input_point, output_point)], secret_scalar, public_key, additional_data)

    @classmethod
    def prove_ios(
        cls,
        ios: list[VrfIo],
        secret_scalar: int,
        public_key: CurvePoint,
        additional_data: bytes,
    ) -> ThinVRF:
        transcript, merged = vrf_transcript(cls.cv, DomSep.THIN_VRF, schnorr_ios(cls.cv, public_key, ios), additional_data)
        k = nonce(cls.cv, secret_scalar, transcript)
        r = merged.input * k
        c = challenge(cls.cv, [r], transcript)
        s = (k + c * secret_scalar) % cls.cv.curve.params.subgroup_order
        output_point = ios[0].output if len(ios) == 1 else merged.output
        return cls(output_point, r, s)

    def verify(self, public_key: bytes, input: bytes, additional_data: bytes, salt: bytes = b"") -> bool:
        input_point = self.cv.encode_to_curve(input, salt)
        try:
            public_key_pt = self.cv.string_to_point(public_key)
        except ValueError as exc:
            raise ValueError("Invalid public key") from exc
        return self.verify_ios(public_key_pt, [VrfIo(input_point, self.output_point)], additional_data)

    def verify_ios(self, public_key: CurvePoint, ios: list[VrfIo], additional_data: bytes) -> bool:
        transcript, merged = vrf_transcript(self.cv, DomSep.THIN_VRF, schnorr_ios(self.cv, public_key, ios), additional_data)
        c = challenge(self.cv, [self.r], transcript)
        lhs = self.cv.msm([merged.input, merged.output], [self.s, -c])
        return lhs == self.r

    @classmethod
    def proof_to_hash(cls, gamma: CurvePoint, mul_cofactor: bool = False) -> bytes:
        if mul_cofactor:
            gamma = gamma * cls.cv.curve.params.cofactor
        return point_to_hash(cls.cv, gamma)


def _batch_coefficients(count: int, order: int) -> list[int]:
    if count == 0:
        return []
    coefficients = [1]
    for _ in range(count - 1):
        coefficient = 0
        while coefficient == 0:
            coefficient = secrets.randbelow(order)
        coefficients.append(coefficient)
    return coefficients


class ThinBatchVerifier:
    def __init__(self, curve: CurveVariant):
        self.cv = curve
        self.items: list[ThinBatchItem] = []

    @classmethod
    def __class_getitem__(cls, curve_variant: CurveVariant | Any) -> type[ThinBatchVerifier] | Any:
        if not isinstance(curve_variant, CurveVariant):
            return cls

        class _SpecializedThinBatchVerifier(cls):
            def __init__(self) -> None:
                super().__init__(curve_variant)

        _SpecializedThinBatchVerifier.__name__ = f"{cls.__name__}[{curve_variant.name}]"
        return _SpecializedThinBatchVerifier

    def push(self, public_key: CurvePoint, ios: list[VrfIo], additional_data: bytes, proof: ThinVRF) -> None:
        chained_ios = schnorr_ios(self.cv, public_key, ios)
        transcript, scalar_stream = vrf_transcript_scalars(self.cv, DomSep.THIN_VRF, chained_ios, additional_data)
        c = challenge(self.cv, [proof.r], transcript)
        self.items.append(ThinBatchItem(c, chained_ios, scalar_stream.take(len(chained_ios)), proof.r, proof.s))

    def verify(self) -> bool:
        if not self.items:
            return True

        points: list[CurvePoint] = []
        scalars: list[int] = []
        order = self.cv.curve.params.subgroup_order
        for coefficient, item in zip(_batch_coefficients(len(self.items), order), self.items, strict=False):
            weighted_c = coefficient * item.c
            weighted_s = coefficient * item.s

            for io, z in zip(item.ios, item.zs, strict=True):
                points.extend([io.input, io.output])
                scalars.extend([weighted_s * z, -(weighted_c * z)])
            points.append(item.r)
            scalars.append(-coefficient)
        return self.cv.msm(points, scalars).is_identity()
