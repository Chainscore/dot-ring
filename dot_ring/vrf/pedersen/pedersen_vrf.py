from __future__ import annotations

from dataclasses import dataclass
from typing import Any, TypeVar, cast

from dot_ring.curve.curve import CurveVariant
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
    vrf_transcript,
)

from ..vrf import VRF

C = TypeVar("C", bound=CurveVariant)


def _blinding_base(curve: CurveVariant) -> CurvePoint:
    if curve.curve.BBx is None or curve.curve.BBy is None:
        raise ValueError(f"{curve.name} does not define a Pedersen blinding base")
    return curve.point(cast(int, curve.curve.BBx), cast(int, curve.curve.BBy))


@dataclass
class PedersenVRF(VRF[C]):
    """
    Pedersen VRF implementation.

    This implementation provides Pedersen-style VRF operations with blinding
    support.

    Usage:
    >>> from dot_ring.curve.specs.bandersnatch import Bandersnatch
    >>> from dot_ring.vrf.pedersen.pedersen import PedersenVRF
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
    def from_bytes(cls, proof: bytes) -> PedersenVRF:
        point_length = cls.cv.curve.POINT_LEN * (2 if cls.cv.curve.UNCOMPRESSED else 1)
        scalar_size = scalar_len(cls.cv)
        expected = 4 * point_length + 2 * scalar_size
        if len(proof) != expected:
            raise ValueError(f"invalid Pedersen VRF proof length: expected {expected}, got {len(proof)}")

        output_point = cls.cv.point.string_to_point(proof[0:point_length])
        public_key_cp = cls.cv.point.string_to_point(proof[point_length : 2 * point_length])
        r = cls.cv.point.string_to_point(proof[2 * point_length : 3 * point_length])
        ok = cls.cv.point.string_to_point(proof[3 * point_length : 4 * point_length])
        s = scalar_decode(cls.cv, proof[4 * point_length : 4 * point_length + scalar_size])
        sb = scalar_decode(cls.cv, proof[4 * point_length + scalar_size :])

        if isinstance(output_point, str) or isinstance(public_key_cp, str) or isinstance(r, str) or isinstance(ok, str):
            raise ValueError("Invalid point in proof")

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
    ) -> PedersenVRF:
        secret_scalar = scalar_decode(cls.cv, secret_key)
        io = cls._io_from_alpha(alpha, secret_scalar, salt)
        public_key = cls.cv.point.generator_point() * secret_scalar
        return cls.prove_ios([io], secret_scalar, public_key, additional_data)

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
        generator = cls.cv.point.generator_point()

        blinded_pk = public_key + blinding_base * blinding_factor
        transcript.absorb_point(blinded_pk)

        k = nonce(cls.cv, secret_scalar, transcript)
        kb = nonce(cls.cv, blinding_factor, transcript)
        result_point = generator * k + blinding_base * kb
        ok = merged.input * k
        c = challenge(cls.cv, [result_point, ok], transcript)
        s = (k + c * secret_scalar) % cls.cv.curve.ORDER
        sb = (kb + c * blinding_factor) % cls.cv.curve.ORDER
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
        input_point = cast(Any, self.cv.point).encode_to_curve(input, salt)
        return self.verify_ios([VrfIo(input_point, self.output_point)], additional_data)

    def verify_ios(self, ios: list[VrfIo], additional_data: bytes) -> bool:
        transcript, merged = vrf_transcript(self.cv, DomSep.PEDERSEN_VRF, ios, additional_data)
        transcript.absorb_point(self.blinded_pk)
        c = challenge(self.cv, [self.result_point, self.ok], transcript)
        blinding_base = _blinding_base(self.cv)
        generator = self.cv.point.generator_point()

        lhs1 = self.cv.point.msm([merged.input, merged.output], [self.s, -c])
        if lhs1 != self.ok:
            return False

        lhs2 = self.cv.point.msm([generator, blinding_base, self.blinded_pk], [self.s, self.sb, -c])
        return lhs2 == self.result_point

    @classmethod
    def blinding_scalar(cls, secret_scalar: int, transcript: Any) -> int:
        t = transcript.clone()
        t.absorb_raw(bytes([DomSep.PEDERSEN_BLINDING]))
        return nonce(cls.cv, secret_scalar, t)

    @classmethod
    def blinding(cls, secret: bytes, input_point: bytes, add: bytes) -> int:
        del input_point, add
        return cls.blinding_scalar(scalar_decode(cls.cv, secret), vrf_transcript(cls.cv, DomSep.PEDERSEN_VRF, [], b"")[0])

    @classmethod
    def proof_to_hash(cls, gamma: CurvePoint, mul_cofactor: bool = False) -> bytes:
        if mul_cofactor:
            gamma = gamma * cls.cv.curve.COFACTOR
        return point_to_hash(cls.cv, gamma)

    @classmethod
    def ecvrf_proof_to_hash(cls, output_point_bytes: bytes | str) -> bytes:
        if not isinstance(output_point_bytes, bytes):
            output_point_bytes = bytes.fromhex(output_point_bytes)
        output_point = cls.cv.point.string_to_point(output_point_bytes)
        if isinstance(output_point, str):
            raise ValueError("Invalid output point")
        return cls.proof_to_hash(output_point)
