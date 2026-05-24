from __future__ import annotations

from dataclasses import dataclass
from typing import Any, cast

from dot_ring.curve.point import CurvePoint
from dot_ring.vrf.transcript import (
    CHALLENGE_LEN,
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
class TinyVRF(VRF[Any]):
    """
    Tiny VRF proof.

    Compact VRF-AD proof using transcript-derived challenges and nonces,
    additional data, and multi-input delinearization.

    Usage:
    >>> from dot_ring.curve.specs.bandersnatch import Bandersnatch
    >>> from dot_ring.vrf.ietf.ietf import TinyVRF
    >>> proof = TinyVRF[Bandersnatch].prove(alpha, secret_key, additional_data)
    >>> verified = proof.verify(public_key, input_point, additional_data)
    """

    output_point: CurvePoint
    c: int
    s: int

    @classmethod
    def from_bytes(cls, proof_bytes: bytes) -> TinyVRF:
        point_len = cls.cv.curve.POINT_LEN * (2 if cls.cv.curve.UNCOMPRESSED else 1)
        scalar_size = scalar_len(cls.cv)
        expected = point_len + CHALLENGE_LEN + scalar_size
        if len(proof_bytes) != expected:
            raise ValueError(f"invalid Tiny VRF proof length: expected {expected}, got {len(proof_bytes)}")
        output_point = cls.cv.point.string_to_point(proof_bytes[:point_len])
        if isinstance(output_point, str):
            raise ValueError("Invalid output point")
        c = int.from_bytes(proof_bytes[point_len : point_len + CHALLENGE_LEN], "little") % cls.cv.curve.ORDER
        s = scalar_decode(cls.cv, proof_bytes[point_len + CHALLENGE_LEN :])
        if s >= cls.cv.curve.ORDER:
            raise ValueError("Response scalar s is not less than the curve order")
        return cls(output_point, c, s)

    def to_bytes(self) -> bytes:
        return self.output_point.point_to_string() + self.c.to_bytes(CHALLENGE_LEN, "little") + scalar_encode(self.cv, self.s)

    @classmethod
    def _io_from_alpha(cls, alpha: bytes, secret_scalar: int, salt: bytes = b"") -> VrfIo:
        input_point = cast(Any, cls.cv.point).encode_to_curve(alpha, salt)
        output_point = input_point * secret_scalar
        return VrfIo(input_point, output_point)

    @classmethod
    def prove(
        cls,
        alpha: bytes,
        secret_key: bytes,
        additional_data: bytes,
        salt: bytes = b"",
    ) -> TinyVRF:
        secret_scalar = scalar_decode(cls.cv, secret_key)
        public_key = cls.cv.point.generator_point() * secret_scalar
        io = cls._io_from_alpha(alpha, secret_scalar, salt)
        return cls.prove_ios([io], secret_scalar, public_key, additional_data)

    @classmethod
    def prove_ios(
        cls,
        ios: list[VrfIo],
        secret_scalar: int,
        public_key: CurvePoint,
        additional_data: bytes,
    ) -> TinyVRF:
        transcript, merged = vrf_transcript(cls.cv, DomSep.TINY_VRF, schnorr_ios(cls.cv, public_key, ios), additional_data)
        k = cls.generate_nonce(secret_scalar, transcript)
        r = merged.input * k
        c = challenge(cls.cv, [r], transcript)
        s = (k + c * secret_scalar) % cls.cv.curve.ORDER
        output_point = ios[0].output if len(ios) == 1 else merged.output
        return cls(output_point, c, s)

    @classmethod
    def generate_nonce(cls, secret_scalar: int, transcript: Any) -> int:
        if not hasattr(transcript, "clone"):
            return super().generate_nonce(secret_scalar, transcript)
        return nonce(cls.cv, secret_scalar, transcript)

    def verify(self, public_key: bytes, input: bytes, additional_data: bytes, salt: bytes = b"") -> bool:
        input_point = cast(Any, self.cv.point).encode_to_curve(input, salt)
        public_key_pt = self.cv.point.string_to_point(public_key)
        if isinstance(public_key_pt, str):
            raise ValueError("Invalid public key")
        io = VrfIo(input_point, self.output_point)
        return self.verify_ios(public_key_pt, [io], additional_data)

    def verify_ios(self, public_key: CurvePoint, ios: list[VrfIo], additional_data: bytes) -> bool:
        transcript, merged = vrf_transcript(self.cv, DomSep.TINY_VRF, schnorr_ios(self.cv, public_key, ios), additional_data)
        r = self.cv.point.msm([merged.input, merged.output], [self.s, -self.c])
        expected_c = challenge(self.cv, [r], transcript)
        return self.c == expected_c

    @classmethod
    def proof_to_hash(cls, gamma: CurvePoint, mul_cofactor: bool = False) -> bytes:
        if mul_cofactor:
            gamma = gamma * cls.cv.curve.COFACTOR
        return point_to_hash(cls.cv, gamma)
