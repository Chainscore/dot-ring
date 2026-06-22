"""Thin VRF (section 3).

The library proof envelope is `gamma || R || s`; the spec proof is `R || s`.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from dot_ring.curve.point import CurvePoint
from dot_ring.vrf.codec import dec_scalar, dec_scalar_mod, enc_point, enc_scalar, point_len, scalar_len, valid_point
from dot_ring.vrf.domain import DomSep
from dot_ring.vrf.primitives import (
    CHALLENGE_LEN,
    VrfIo,
    challenge,
    nonce,
    point_to_hash,
    squeeze_transcript_bytes,
    vrf_transcript,
    vrf_transcript_scalars,
)

from ..vrf import VRF


@dataclass
class _ThinBatchItem:
    c: int
    ios: list[VrfIo]
    zs: list[int]
    r: CurvePoint
    s: int


@dataclass
class ThinVRF(VRF[Any]):
    """Batch-friendly VRF-AD proof. Fields after `output_point` are spec proof `(R, s)`."""

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
            output_point = cls.cv.point_type.string_to_point(proof_bytes[:encoded_point_len])
            r = cls.cv.point_type.string_to_point(proof_bytes[encoded_point_len : 2 * encoded_point_len])
        except ValueError as exc:
            raise ValueError("Invalid point in proof") from exc
        s = dec_scalar(cls.cv, proof_bytes[2 * encoded_point_len :])
        if not (valid_point(output_point) and valid_point(r)):
            raise ValueError("Invalid identity or subgroup point in proof")
        return cls(output_point, r, s)

    def encode(self) -> bytes:
        return enc_point(self.output_point) + enc_point(self.r) + enc_scalar(self.cv, self.s)

    @classmethod
    def prove(
        cls,
        alpha: bytes,
        secret_key: bytes,
        additional_data: bytes,
        salt: bytes = b"",
    ) -> ThinVRF:
        secret_scalar = dec_scalar_mod(cls.cv, secret_key)
        public_key = cls.cv.point_type.generator_point() * secret_scalar
        input_point = cls.cv.point_type.encode_to_curve(alpha, salt)
        output_point = input_point * secret_scalar
        transcript, merged = vrf_transcript(
            cls.cv,
            DomSep.THIN_VRF,
            [VrfIo(cls.cv.point_type.generator_point(), public_key), VrfIo(input_point, output_point)],
            additional_data,
        )
        k = nonce(cls.cv, secret_scalar, transcript)
        r = merged.input * k
        c = challenge(cls.cv, [r], transcript)
        s = (k + c * secret_scalar) % cls.cv.curve.params.subgroup_order
        return cls(output_point, r, s)

    def verify(self, public_key: bytes, input: bytes, additional_data: bytes, salt: bytes = b"") -> bool:
        input_point = self.cv.point_type.encode_to_curve(input, salt)
        try:
            public_key_point = self.cv.point_type.string_to_point(public_key)
        except ValueError as exc:
            raise ValueError("Invalid public key") from exc
        if not (valid_point(public_key_point) and valid_point(self.r) and valid_point(input_point) and valid_point(self.output_point)):
            return False
        transcript, merged = vrf_transcript(
            self.cv,
            DomSep.THIN_VRF,
            [VrfIo(self.cv.point_type.generator_point(), public_key_point), VrfIo(input_point, self.output_point)],
            additional_data,
        )
        c = challenge(self.cv, [self.r], transcript)
        return self.cv.point_type.msm([merged.input, merged.output], [self.s, -c]) == self.r

    @classmethod
    def proof_to_hash(cls, gamma: CurvePoint, mul_cofactor: bool = False) -> bytes:
        if mul_cofactor:
            gamma = gamma * cls.cv.curve.params.cofactor
        return point_to_hash(cls.cv, gamma)

    @classmethod
    def batch_verify(
        cls,
        proofs: Sequence[ThinVRF],
        public_keys: Sequence[bytes],
        inputs: Sequence[bytes],
        additional_data: Sequence[bytes],
        salts: Sequence[bytes] | None = None,
    ) -> bool:
        if salts is None:
            salts = [b""] * len(proofs)

        items: list[_ThinBatchItem] = []
        try:
            for proof, public_key, input_value, ad, salt in zip(proofs, public_keys, inputs, additional_data, salts, strict=True):
                input_point = cls.cv.point_type.encode_to_curve(input_value, salt)
                public_key_point = cls.cv.point_type.string_to_point(public_key)
                if not (valid_point(public_key_point) and valid_point(proof.r) and valid_point(input_point) and valid_point(proof.output_point)):
                    return False
                ios = [VrfIo(cls.cv.point_type.generator_point(), public_key_point), VrfIo(input_point, proof.output_point)]
                transcript, scalars = vrf_transcript_scalars(cls.cv, DomSep.THIN_VRF, ios, ad)
                items.append(_ThinBatchItem(challenge(cls.cv, [proof.r], transcript), ios, scalars, proof.r, proof.s))
        except (AttributeError, TypeError, ValueError):
            return False

        if not items:
            return True

        absorbed = bytearray(cls.cv.curve.params.suite_id)
        absorbed.append(DomSep.BATCH_VERIFY)
        for item in items:
            absorbed.extend(enc_scalar(cls.cv, item.c))
            absorbed.extend(enc_scalar(cls.cv, item.s))

        raw = squeeze_transcript_bytes(cls.cv.curve.params.hash_fn, bytes(absorbed), CHALLENGE_LEN * len(items))
        points: list[CurvePoint] = []
        msm_scalars: list[int] = []
        for index, item in enumerate(items):
            coefficient = dec_scalar_mod(cls.cv, raw[CHALLENGE_LEN * index : CHALLENGE_LEN * (index + 1)])
            weighted_c = coefficient * item.c
            weighted_s = coefficient * item.s

            for io, z in zip(item.ios, item.zs, strict=True):
                points.extend([io.input, io.output])
                msm_scalars.extend([weighted_s * z, -(weighted_c * z)])
            points.append(item.r)
            msm_scalars.append(-coefficient)
        return cls.cv.point_type.msm(points, msm_scalars).is_identity()
