"""Pedersen VRF (section 4).

The library proof envelope is `gamma || Y_bar || R || O_k || s || s_b`;
the spec proof is `Y_bar || R || O_k || s || s_b`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
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

from ..vrf import VRF

C = TypeVar("C", bound=CurveVariant)


def _blinding_base(curve: CurveVariant) -> CurvePoint:
    blinding_base = curve.curve.params.auxiliary_points.blinding_base
    if blinding_base is None:
        raise ValueError(f"{curve.name} does not define a Pedersen blinding base")
    return curve.point(blinding_base[0], blinding_base[1])


@dataclass(frozen=True)
class PedersenVRF(VRF[C]):
    """Pedersen VRF proof plus gamma envelope. `_blinding_factor` is prover-local for Ring VRF."""

    output_point: CurvePoint
    blinded_pk: CurvePoint
    result_point: CurvePoint
    ok: CurvePoint
    s: int
    sb: int
    _blinding_factor: int = 0
    _points_validated: bool = field(default=False, repr=False, compare=False)

    @classmethod
    def proof_len(cls) -> int:
        point_length = point_len(cls.cv)
        return 4 * point_length + 2 * scalar_len(cls.cv)

    @classmethod
    def decode(cls, proof: bytes) -> PedersenVRF:
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
        if not all(cls._valid_point(point) for point in (output_point, public_key_cp, r, ok)):
            raise ValueError("Invalid identity or subgroup point in proof")

        return cls(
            output_point=output_point,
            blinded_pk=public_key_cp,
            result_point=r,
            ok=ok,
            s=s,
            sb=sb,
            _points_validated=True,
        )

    def encode(self) -> bytes:
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
        secret_scalar = scalar_decode(cls.cv, secret_key)
        public_key = cls.cv.generator_point() * secret_scalar
        io = cls._io_from_alpha(alpha, secret_scalar, salt)
        return cls._prove_ios([io], secret_scalar, public_key, additional_data, points_validated=True)

    @classmethod
    def prove_ios(
        cls,
        ios: list[VrfIo],
        secret_scalar: int,
        public_key: CurvePoint,
        additional_data: bytes,
    ) -> PedersenVRF:
        return cls._prove_ios(ios, secret_scalar, public_key, additional_data, points_validated=False)

    @classmethod
    def _prove_ios(
        cls,
        ios: list[VrfIo],
        secret_scalar: int,
        public_key: CurvePoint,
        additional_data: bytes,
        *,
        points_validated: bool,
    ) -> PedersenVRF:
        """Spec section 4.1 steps 1-10 over caller-supplied I/O pairs."""
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
            _points_validated=points_validated,
        )

    def verify(self, input: bytes, additional_data: bytes, salt: bytes = b"") -> bool:
        if not self._valid_proof_points():
            return False
        input_point = self.cv.encode_to_curve(input, salt)
        return self._verify_ios([VrfIo(input_point, self.output_point)], additional_data)

    def verify_ios(self, ios: list[VrfIo], additional_data: bytes) -> bool:
        """Spec section 4.2: validate points, rebuild `T`, then check VRF and commitment equations."""
        if not self._valid_proof_points() or not self._valid_ios(ios):
            return False
        return self._verify_ios(ios, additional_data)

    def _valid_proof_points(self) -> bool:
        if self._points_validated:
            return True
        return all(self._valid_point(point) for point in (self.output_point, self.blinded_pk, self.result_point, self.ok))

    @classmethod
    def _valid_ios(cls, ios: list[VrfIo]) -> bool:
        seen: set[int] = set()
        for io in ios:
            for point in (io.input, io.output):
                point_id = id(point)
                if point_id in seen:
                    continue
                seen.add(point_id)
                if not cls._valid_point(point):
                    return False
        return True

    def _verify_ios(self, ios: list[VrfIo], additional_data: bytes) -> bool:
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

    def verify_unblinding(self, public_key: bytes | str | CurvePoint, blinding_factor: int) -> bool:
        """Spec section 4.3: check `Y_bar = Y + b*B` for a revealed blinding factor."""
        order = self.cv.curve.params.subgroup_order
        if not 0 <= blinding_factor < order:
            return False
        if isinstance(public_key, bytes | str):
            try:
                public_key = self.cv.string_to_point(public_key)
            except ValueError as exc:
                raise ValueError("Invalid public key") from exc
        blinded_pk_valid = self._points_validated or self._valid_point(self.blinded_pk)
        if not (self._valid_point(public_key) and blinded_pk_valid):
            return False
        return public_key + _blinding_base(self.cv) * blinding_factor == self.blinded_pk

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
