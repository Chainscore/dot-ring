"""Tiny VRF (section 2).

The library proof envelope is `gamma || c || s`; the spec proof is `c || s`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from dot_ring.curve.point import CurvePoint
from dot_ring.vrf.codec import dec_point, dec_scalar, dec_scalar_mod, enc_point, enc_scalar, point_len, scalar_len
from dot_ring.vrf.domain import DomSep
from dot_ring.vrf.primitives import (
    CHALLENGE_LEN,
    VrfIo,
    challenge,
    nonce,
    point_to_hash,
    vrf_transcript,
)

from ..vrf import VRF


@dataclass
class TinyVRF(VRF[Any]):
    """Compact VRF-AD proof. Fields after `output_point` are spec proof `(c, s)`."""

    output_point: CurvePoint
    c: int
    s: int

    @classmethod
    def decode(cls, proof_bytes: bytes) -> TinyVRF:
        encoded_point_len = point_len(cls.cv)
        scalar_size = scalar_len(cls.cv)
        expected = encoded_point_len + CHALLENGE_LEN + scalar_size
        if len(proof_bytes) != expected:
            raise ValueError(f"invalid Tiny VRF proof length: expected {expected}, got {len(proof_bytes)}")
        try:
            output_point = dec_point(cls.cv, proof_bytes[:encoded_point_len])
        except ValueError as exc:
            raise ValueError("Invalid output point") from exc
        c = dec_scalar_mod(cls.cv, proof_bytes[encoded_point_len : encoded_point_len + CHALLENGE_LEN])
        s = dec_scalar(cls.cv, proof_bytes[encoded_point_len + CHALLENGE_LEN :])
        return cls(output_point, c, s)

    def encode(self) -> bytes:
        return enc_point(self.output_point) + self.c.to_bytes(CHALLENGE_LEN, "little") + enc_scalar(self.cv, self.s)

    @classmethod
    def prove(
        cls,
        alpha: bytes,
        secret_key: bytes,
        additional_data: bytes,
        salt: bytes = b"",
    ) -> TinyVRF:
        secret_scalar = dec_scalar_mod(cls.cv, secret_key)
        public_key = cls.cv.point_type.generator_point() * secret_scalar
        input_point = cls.cv.point_type.encode_to_curve(alpha, salt)
        output_point = input_point * secret_scalar
        ios = [VrfIo(cls.cv.point_type.generator_point(), public_key), VrfIo(input_point, output_point)]
        transcript, merged = vrf_transcript(cls.cv, DomSep.TINY_VRF, ios, additional_data)
        k = nonce(cls.cv, secret_scalar, transcript)
        r = merged.input * k
        c = challenge(cls.cv, [r], transcript)
        s = (k + c * secret_scalar) % cls.cv.curve.params.subgroup_order
        return cls(output_point, c, s)

    def verify(self, public_key: bytes, input: bytes, additional_data: bytes, salt: bytes = b"") -> bool:
        input_point = self.cv.point_type.encode_to_curve(input, salt)
        try:
            public_key_pt = dec_point(self.cv, public_key)
        except ValueError as exc:
            raise ValueError("Invalid public key") from exc

        ios = [VrfIo(self.cv.point_type.generator_point(), public_key_pt), VrfIo(input_point, self.output_point)]
        transcript, merged = vrf_transcript(self.cv, DomSep.TINY_VRF, ios, additional_data)
        r = self.cv.point_type.msm([merged.input, merged.output], [self.s, -self.c])
        expected_c = challenge(self.cv, [r], transcript)
        return self.c == expected_c

    @classmethod
    def proof_to_hash(cls, gamma: CurvePoint, mul_cofactor: bool = False) -> bytes:
        if mul_cofactor:
            gamma = gamma * cls.cv.curve.params.cofactor
        return point_to_hash(cls.cv, gamma)
