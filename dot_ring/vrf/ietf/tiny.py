from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from dot_ring.curve.point import CurvePoint
from dot_ring.vrf.transcript import (
    CHALLENGE_LEN,
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

from ..vrf import VRF, PreparedSecretKey


@dataclass
class TinyVRF(VRF[Any]):
    """
    Tiny VRF proof.

    Compact VRF-AD proof using transcript-derived challenges and nonces,
    additional data, and multi-input delinearization.

    Usage:
    >>> from dot_ring.curve.specs.bandersnatch import Bandersnatch
    >>> from dot_ring.vrf.ietf import TinyVRF
    >>> proof = TinyVRF[Bandersnatch].prove(alpha, secret_key, additional_data)
    >>> verified = proof.verify(public_key, input_point, additional_data)
    """

    output_point: CurvePoint
    c: int
    s: int

    @classmethod
    def from_bytes(cls, proof_bytes: bytes) -> TinyVRF:
        encoded_point_len = point_len(cls.cv)
        scalar_size = scalar_len(cls.cv)
        expected = encoded_point_len + CHALLENGE_LEN + scalar_size
        if len(proof_bytes) != expected:
            raise ValueError(f"invalid Tiny VRF proof length: expected {expected}, got {len(proof_bytes)}")
        try:
            output_point = cls.cv.string_to_point(proof_bytes[:encoded_point_len])
        except ValueError as exc:
            raise ValueError("Invalid output point") from exc
        order = cls.cv.curve.params.subgroup_order
        c = int.from_bytes(proof_bytes[encoded_point_len : encoded_point_len + CHALLENGE_LEN], "little") % order
        s = scalar_decode(cls.cv, proof_bytes[encoded_point_len + CHALLENGE_LEN :])
        if s >= order:
            raise ValueError("Response scalar s is not less than the curve order")
        return cls(output_point, c, s)

    def to_bytes(self) -> bytes:
        return self.output_point.point_to_string() + self.c.to_bytes(CHALLENGE_LEN, "little") + scalar_encode(self.cv, self.s)

    @classmethod
    def _io_from_alpha(cls, alpha: bytes, secret_scalar: int, salt: bytes = b"") -> VrfIo:
        input_point = cls.cv.encode_to_curve(alpha, salt)
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
        return cls.prove_prepared(alpha, cls.prepare_secret_key(secret_key), additional_data, salt)

    @classmethod
    def prove_prepared(
        cls,
        alpha: bytes,
        secret_key: PreparedSecretKey[Any],
        additional_data: bytes,
        salt: bytes = b"",
    ) -> TinyVRF:
        if secret_key.curve is not cls.cv:
            raise ValueError("prepared secret key uses a different curve")
        io = cls._io_from_alpha(alpha, secret_key.secret_scalar, salt)
        return cls.prove_ios([io], secret_key.secret_scalar, secret_key.public_key, additional_data)

    @classmethod
    def prove_ios(
        cls,
        ios: list[VrfIo],
        secret_scalar: int,
        public_key: CurvePoint,
        additional_data: bytes,
    ) -> TinyVRF:
        if len(ios) == 1:
            transcript, scalars = vrf_transcript_scalars(
                cls.cv,
                DomSep.TINY_VRF,
                schnorr_ios(cls.cv, public_key, ios),
                additional_data,
            )
            z0 = scalars.next()
            z1 = scalars.next()
            k = nonce(cls.cv, secret_scalar, transcript)
            generator = cls.cv.generator_point()
            order = cls.cv.curve.params.subgroup_order
            r = cls.cv.msm(
                [generator, ios[0].input],
                [(k * z0) % order, (k * z1) % order],
            )
            c = challenge(cls.cv, [r], transcript)
            s = (k + c * secret_scalar) % order
            return cls(ios[0].output, c, s)

        transcript, merged = vrf_transcript(cls.cv, DomSep.TINY_VRF, schnorr_ios(cls.cv, public_key, ios), additional_data)
        k = nonce(cls.cv, secret_scalar, transcript)
        r = merged.input * k
        c = challenge(cls.cv, [r], transcript)
        s = (k + c * secret_scalar) % cls.cv.curve.params.subgroup_order
        output_point = ios[0].output if len(ios) == 1 else merged.output
        return cls(output_point, c, s)

    def verify(self, public_key: bytes, input: bytes, additional_data: bytes, salt: bytes = b"") -> bool:
        input_point = self.cv.encode_to_curve(input, salt)
        try:
            public_key_pt = self.cv.string_to_point(public_key)
        except ValueError as exc:
            raise ValueError("Invalid public key") from exc
        io = VrfIo(input_point, self.output_point)
        return self.verify_ios(public_key_pt, [io], additional_data)

    def verify_ios(self, public_key: CurvePoint, ios: list[VrfIo], additional_data: bytes) -> bool:
        if len(ios) == 1:
            transcript, scalars = vrf_transcript_scalars(
                self.cv,
                DomSep.TINY_VRF,
                schnorr_ios(self.cv, public_key, ios),
                additional_data,
            )
            z0 = scalars.next()
            z1 = scalars.next()
            generator = self.cv.generator_point()
            order = self.cv.curve.params.subgroup_order
            r = self.cv.msm(
                [generator, ios[0].input, public_key, ios[0].output],
                [
                    (self.s * z0) % order,
                    (self.s * z1) % order,
                    (-self.c * z0) % order,
                    (-self.c * z1) % order,
                ],
            )
            expected_c = challenge(self.cv, [r], transcript)
            return self.c == expected_c

        transcript, merged = vrf_transcript(self.cv, DomSep.TINY_VRF, schnorr_ios(self.cv, public_key, ios), additional_data)
        r = self.cv.msm([merged.input, merged.output], [self.s, -self.c])
        expected_c = challenge(self.cv, [r], transcript)
        return self.c == expected_c

    @classmethod
    def proof_to_hash(cls, gamma: CurvePoint, mul_cofactor: bool = False) -> bytes:
        if mul_cofactor:
            gamma = gamma * cls.cv.curve.params.cofactor
        return point_to_hash(cls.cv, gamma)

    @classmethod
    def ecvrf_decode_proof(cls, proof: bytes | str) -> tuple[CurvePoint, int, int]:
        if not isinstance(proof, bytes):
            proof = bytes.fromhex(proof)

        encoded_point_len = point_len(cls.cv)
        scalar_size = scalar_len(cls.cv)
        expected = encoded_point_len + CHALLENGE_LEN + scalar_size
        if len(proof) != expected:
            raise ValueError(f"invalid Tiny VRF proof length: expected {expected}, got {len(proof)}")

        try:
            output_point = cls.cv.string_to_point(proof[:encoded_point_len])
        except ValueError as exc:
            raise ValueError("Invalid gamma point") from exc

        order = cls.cv.curve.params.subgroup_order
        c = int.from_bytes(proof[encoded_point_len : encoded_point_len + CHALLENGE_LEN], "little") % order
        s = scalar_decode(cls.cv, proof[encoded_point_len + CHALLENGE_LEN :])
        if s >= order:
            raise ValueError("Response scalar S is not less than the curve order")
        return output_point, c, s

    @classmethod
    def ecvrf_proof_to_hash(cls, proof: bytes | str) -> bytes:
        output_point, _, _ = cls.ecvrf_decode_proof(proof)
        return cls.proof_to_hash(output_point)
