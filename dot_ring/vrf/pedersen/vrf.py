from __future__ import annotations

from dataclasses import dataclass
from typing import Any, TypeVar

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
    vrf_transcript,
)

from ..vrf import VRF, PreparedSecretKey

C = TypeVar("C", bound=CurveVariant)


def _blinding_base(curve: CurveVariant) -> CurvePoint:
    blinding_base = curve.curve.params.auxiliary_points.blinding_base
    if blinding_base is None:
        raise ValueError(f"{curve.name} does not define a Pedersen blinding base")
    return curve.point(blinding_base[0], blinding_base[1])


@dataclass
class PedersenVRF(VRF[C]):
    """
    Pedersen VRF implementation.

    This implementation provides Pedersen-style VRF operations with blinding
    support.

    Usage:
    >>> from dot_ring.curve.specs.bandersnatch import Bandersnatch
    >>> from dot_ring.vrf.pedersen import PedersenVRF
    >>> proof = PedersenVRF[Bandersnatch].prove(alpha, secret_key, additional_data)
    >>> verified = PedersenVRF[Bandersnatch].verify(input_point, additional_data, proof)
    """

    output_point: CurvePoint
    blinded_pk: CurvePoint
    result_point: CurvePoint
    ok: CurvePoint
    s: int
    sb: int
    _blinding_factor: int = 0

    @classmethod
    def proof_len(cls) -> int:
        point_length = point_len(cls.cv)
        return 4 * point_length + 2 * scalar_len(cls.cv)

    @classmethod
    def from_bytes(cls, proof: bytes) -> PedersenVRF:
        point_length = point_len(cls.cv)
        scalar_size = scalar_len(cls.cv)
        expected = cls.proof_len()
        if len(proof) != expected:
            raise ValueError(f"invalid Pedersen VRF proof length: expected {expected}, got {len(proof)}")

        try:
            output_point = cls.cv.string_to_point(proof[0:point_length])
            public_key_cp = cls.cv.string_to_point(proof[point_length : 2 * point_length])
            r = cls.cv.string_to_point(proof[2 * point_length : 3 * point_length])
            ok = cls.cv.string_to_point(proof[3 * point_length : 4 * point_length])
        except ValueError as exc:
            raise ValueError("Invalid point in proof") from exc
        s = scalar_decode(cls.cv, proof[4 * point_length : 4 * point_length + scalar_size])
        sb = scalar_decode(cls.cv, proof[4 * point_length + scalar_size :])
        order = cls.cv.curve.params.subgroup_order
        if s >= order:
            raise ValueError("Response scalar s is not canonical")
        if sb >= order:
            raise ValueError("Response scalar sb is not canonical")

        return cls(
            output_point=output_point,
            blinded_pk=public_key_cp,
            result_point=r,
            ok=ok,
            s=s,
            sb=sb,
        )

    def to_bytes(self) -> bytes:
        return (
            self.output_point.point_to_string()
            + self.blinded_pk.point_to_string()
            + self.result_point.point_to_string()
            + self.ok.point_to_string()
            + scalar_encode(self.cv, self.s)
            + scalar_encode(self.cv, self.sb)
        )

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
    ) -> PedersenVRF:
        return cls.prove_prepared(alpha, cls.prepare_secret_key(secret_key), additional_data, salt)

    @classmethod
    def prove_prepared(
        cls,
        alpha: bytes,
        secret_key: PreparedSecretKey[Any],
        additional_data: bytes,
        salt: bytes = b"",
    ) -> PedersenVRF:
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
    ) -> PedersenVRF:
        transcript, merged = vrf_transcript(cls.cv, DomSep.PEDERSEN_VRF, ios, additional_data)
        blinding_factor = cls.blinding_scalar(secret_scalar, transcript)
        blinding_base = _blinding_base(cls.cv)
        generator = cls.cv.generator_point()

        blinded_pk = public_key + blinding_base * blinding_factor
        transcript.absorb(blinded_pk.point_to_string())

        k = nonce(cls.cv, secret_scalar, transcript)
        kb = nonce(cls.cv, blinding_factor, transcript)
        result_point = cls.cv.msm([generator, blinding_base], [k, kb])
        ok = merged.input * k
        c = challenge(cls.cv, [result_point, ok], transcript)
        order = cls.cv.curve.params.subgroup_order
        s = (k + c * secret_scalar) % order
        sb = (kb + c * blinding_factor) % order
        output_point = ios[0].output if len(ios) == 1 else merged.output

        return cls(
            output_point=output_point,
            blinded_pk=blinded_pk,
            result_point=result_point,
            ok=ok,
            s=s,
            sb=sb,
            _blinding_factor=blinding_factor,
        )

    def verify(self, input: bytes, additional_data: bytes, salt: bytes = b"") -> bool:
        input_point = self.cv.encode_to_curve(input, salt)
        return self.verify_ios([VrfIo(input_point, self.output_point)], additional_data)

    def verify_ios(self, ios: list[VrfIo], additional_data: bytes) -> bool:
        transcript, merged = vrf_transcript(self.cv, DomSep.PEDERSEN_VRF, ios, additional_data)
        transcript.absorb(self.blinded_pk.point_to_string())
        c = challenge(self.cv, [self.result_point, self.ok], transcript)
        blinding_base = _blinding_base(self.cv)
        generator = self.cv.generator_point()

        lhs1 = self.cv.msm([merged.input, merged.output], [self.s, -c])
        if lhs1 != self.ok:
            return False

        lhs2 = self.cv.msm([generator, blinding_base, self.blinded_pk], [self.s, self.sb, -c])
        return lhs2 == self.result_point

    @classmethod
    def blinding_scalar(cls, secret_scalar: int, transcript: Any) -> int:
        t = transcript.copy()
        t.absorb(bytes([DomSep.PEDERSEN_BLINDING]))
        return nonce(cls.cv, secret_scalar, t)

    @classmethod
    def proof_to_hash(cls, gamma: CurvePoint, mul_cofactor: bool = False) -> bytes:
        if mul_cofactor:
            gamma = gamma * cls.cv.curve.params.cofactor
        return point_to_hash(cls.cv, gamma)

    @classmethod
    def ecvrf_proof_to_hash(cls, output_point_bytes: bytes | str) -> bytes:
        if not isinstance(output_point_bytes, bytes):
            output_point_bytes = bytes.fromhex(output_point_bytes)
        try:
            output_point = cls.cv.string_to_point(output_point_bytes)
        except ValueError as exc:
            raise ValueError("Invalid output point") from exc
        return cls.proof_to_hash(output_point)
