from __future__ import annotations

from dataclasses import dataclass
from typing import Any, cast

from dot_ring.curve.point import CurvePoint
from dot_ring.vrf.transcript import (
    DomSep,
    VrfIo,
    challenge,
    nonce,
    point_to_hash,
    scalar_decode,
    scalar_encode,
    scalar_len,
    schnorr_ios,
    vrf_transcript,
)

from ..vrf import VRF


@dataclass
class ThinVRF(VRF[Any]):
    """Batch-friendly VRF-AD proof storing the nonce commitment."""

    output_point: CurvePoint
    r: CurvePoint
    s: int

    @classmethod
    def from_bytes(cls, proof_bytes: bytes) -> ThinVRF:
        point_len = cls.cv.curve.POINT_LEN * (2 if cls.cv.curve.UNCOMPRESSED else 1)
        scalar_size = scalar_len(cls.cv)
        expected = 2 * point_len + scalar_size
        if len(proof_bytes) != expected:
            raise ValueError(f"invalid Thin VRF proof length: expected {expected}, got {len(proof_bytes)}")
        try:
            output_point = cls.cv.point.string_to_point(proof_bytes[:point_len])
            r = cls.cv.point.string_to_point(proof_bytes[point_len : 2 * point_len])
        except ValueError as exc:
            raise ValueError("Invalid point in proof") from exc
        s = scalar_decode(cls.cv, proof_bytes[2 * point_len :])
        if s >= cls.cv.curve.ORDER:
            raise ValueError("Response scalar s is not less than the curve order")
        return cls(output_point, r, s)

    def to_bytes(self) -> bytes:
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
        public_key = cls.cv.point.generator_point() * secret_scalar
        input_point = cast(Any, cls.cv.point).encode_to_curve(alpha, salt)
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
        s = (k + c * secret_scalar) % cls.cv.curve.ORDER
        output_point = ios[0].output if len(ios) == 1 else merged.output
        return cls(output_point, r, s)

    def verify(self, public_key: bytes, input: bytes, additional_data: bytes, salt: bytes = b"") -> bool:
        input_point = cast(Any, self.cv.point).encode_to_curve(input, salt)
        try:
            public_key_pt = self.cv.point.string_to_point(public_key)
        except ValueError as exc:
            raise ValueError("Invalid public key") from exc
        return self.verify_ios(public_key_pt, [VrfIo(input_point, self.output_point)], additional_data)

    def verify_ios(self, public_key: CurvePoint, ios: list[VrfIo], additional_data: bytes) -> bool:
        transcript, merged = vrf_transcript(self.cv, DomSep.THIN_VRF, schnorr_ios(self.cv, public_key, ios), additional_data)
        c = challenge(self.cv, [self.r], transcript)
        lhs = self.cv.point.msm([merged.input, merged.output], [self.s, -c])
        return lhs == self.r

    @classmethod
    def proof_to_hash(cls, gamma: CurvePoint, mul_cofactor: bool = False) -> bytes:
        if mul_cofactor:
            gamma = gamma * cls.cv.curve.COFACTOR
        return point_to_hash(cls.cv, gamma)
