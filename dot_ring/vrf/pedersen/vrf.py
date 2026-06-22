"""Pedersen VRF (section 4).

The library proof envelope is `gamma || Y_bar || R || O_k || s || s_b`;
the spec proof is `Y_bar || R || O_k || s || s_b`.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any, TypeVar

from dot_ring.curve.curve import CurveVariant
from dot_ring.curve.point import CurvePoint
from dot_ring.vrf.codec import dec_scalar, dec_scalar_mod, enc_64, enc_point, enc_scalar, point_len, scalar_len, valid_point
from dot_ring.vrf.domain import DomSep
from dot_ring.vrf.primitives import (
    CHALLENGE_LEN,
    VrfIo,
    challenge,
    nonce,
    point_to_hash,
    squeeze_transcript_bytes,
    vrf_transcript,
)
from dot_ring.vrf.vrf import VRF

C = TypeVar("C", bound=CurveVariant)


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
            output_point = cls.cv.point_type.string_to_point(proof[0:point_length])
            public_key_cp = cls.cv.point_type.string_to_point(proof[point_length : 2 * point_length])
            r = cls.cv.point_type.string_to_point(proof[2 * point_length : 3 * point_length])
            ok = cls.cv.point_type.string_to_point(proof[3 * point_length : 4 * point_length])
        except ValueError as exc:
            raise ValueError("Invalid point in proof") from exc
        s = dec_scalar(cls.cv, proof[4 * point_length : 4 * point_length + scalar_size])
        sb = dec_scalar(cls.cv, proof[4 * point_length + scalar_size :])
        if not all(valid_point(point) for point in (output_point, public_key_cp, r, ok)):
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
            enc_point(self.output_point)
            + enc_point(self.blinded_pk)
            + enc_point(self.result_point)
            + enc_point(self.ok)
            + enc_scalar(self.cv, self.s)
            + enc_scalar(self.cv, self.sb)
        )

    @classmethod
    def prove(
        cls,
        alpha: bytes,
        secret_key: bytes,
        additional_data: bytes,
        salt: bytes = b"",
    ) -> PedersenVRF:
        secret_scalar = dec_scalar_mod(cls.cv, secret_key)
        public_key = cls.cv.point_type.generator_point() * secret_scalar
        input_point = cls.cv.point_type.encode_to_curve(alpha, salt)
        output_point = input_point * secret_scalar
        io = VrfIo(input_point, output_point)

        transcript, merged = vrf_transcript(cls.cv, DomSep.PEDERSEN_VRF, [io], additional_data)
        blinding_factor = cls.blinding_scalar(secret_scalar, transcript)
        if not cls.cv.curve.params.auxiliary_points.blinding_base:
            raise ValueError("Curve does not have a blinding base point for Pedersen VRF")
        blinding_base = cls.cv.point_type(*cls.cv.curve.params.auxiliary_points.blinding_base)
        generator = cls.cv.point_type.generator_point()

        blinded_pk = public_key + blinding_base * blinding_factor
        transcript.absorb(enc_point(blinded_pk))

        k = nonce(cls.cv, secret_scalar, transcript)
        kb = nonce(cls.cv, blinding_factor, transcript)
        result_point = cls.cv.point_type.msm([generator, blinding_base], [k, kb])
        ok = merged.input * k
        c = challenge(cls.cv, [result_point, ok], transcript)
        order = cls.cv.curve.params.subgroup_order
        s = (k + c * secret_scalar) % order
        sb = (kb + c * blinding_factor) % order

        return cls(
            output_point=output_point,
            blinded_pk=blinded_pk,
            result_point=result_point,
            ok=ok,
            s=s,
            sb=sb,
            _blinding_factor=blinding_factor,
            _points_validated=True,
        )

    def verify(self, input: bytes, additional_data: bytes, salt: bytes = b"") -> bool:
        if not self._valid_proof_points():
            return False
        input_point = self.cv.point_type.encode_to_curve(input, salt)
        transcript, merged = vrf_transcript(self.cv, DomSep.PEDERSEN_VRF, [VrfIo(input_point, self.output_point)], additional_data)
        transcript.absorb(enc_point(self.blinded_pk))
        c = challenge(self.cv, [self.result_point, self.ok], transcript)
        if not self.cv.curve.params.auxiliary_points.blinding_base:
            raise ValueError("Curve does not have a blinding base point for Pedersen VRF")
        blinding_base = self.cv.point_type(*self.cv.curve.params.auxiliary_points.blinding_base)
        generator = self.cv.point_type.generator_point()

        lhs1 = self.cv.point_type.msm([merged.input, merged.output], [self.s, -c])
        if lhs1 != self.ok:
            return False

        lhs2 = self.cv.point_type.msm([generator, blinding_base, self.blinded_pk], [self.s, self.sb, -c])
        return lhs2 == self.result_point

    def _valid_proof_points(self) -> bool:
        if self._points_validated:
            return True
        return all(valid_point(point) for point in (self.output_point, self.blinded_pk, self.result_point, self.ok))

    @classmethod
    def _valid_ios(cls, ios: list[VrfIo]) -> bool:
        seen: set[int] = set()
        for io in ios:
            for point in (io.input, io.output):
                point_id = id(point)
                if point_id in seen:
                    continue
                seen.add(point_id)
                if not valid_point(point):
                    return False
        return True

    def verify_unblinding(self, public_key: bytes | str | CurvePoint, blinding_factor: int) -> bool:
        """Spec section 4.3: check `Y_bar = Y + b*B` for a revealed blinding factor."""
        order = self.cv.curve.params.subgroup_order
        if not 0 <= blinding_factor < order:
            return False
        if isinstance(public_key, bytes | str):
            try:
                public_key = self.cv.point_type.string_to_point(public_key)
            except ValueError as exc:
                raise ValueError("Invalid public key") from exc
        blinded_pk_valid = self._points_validated or valid_point(self.blinded_pk)
        if not (valid_point(public_key) and blinded_pk_valid):
            return False
        if not self.cv.curve.params.auxiliary_points.blinding_base:
            raise ValueError("Curve does not have a blinding base point for Pedersen VRF")
        blinding_base = self.cv.point_type(*self.cv.curve.params.auxiliary_points.blinding_base)

        return public_key + blinding_base * blinding_factor == self.blinded_pk

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
            output_point = cls.cv.point_type.string_to_point(output_point_bytes)
        except ValueError as exc:
            raise ValueError("Invalid output point") from exc
        return cls.proof_to_hash(output_point)

    @classmethod
    def batch_verify(
        cls,
        proofs: Sequence[PedersenVRF],
        inputs: Sequence[bytes],
        additional_data: Sequence[bytes],
        salts: Sequence[bytes] | None = None,
    ) -> bool:
        if salts is None:
            salts = [b""] * len(proofs)

        input_points: list[CurvePoint] = []
        try:
            for input_value, salt in zip(inputs, salts, strict=True):
                input_points.append(cls.cv.point_type.encode_to_curve(input_value, salt))
        except (AttributeError, TypeError, ValueError):
            return False
        batch_items: list[tuple[PedersenVRF, CurvePoint, int]] = []
        order = cls.cv.curve.params.subgroup_order
        half_order = order >> 1
        coefficient_item_bytes = bytearray()

        try:
            for proof, input_point, ad in zip(proofs, input_points, additional_data, strict=True):
                if proof.cv.name != cls.cv.name or not proof._valid_proof_points():
                    return False

                absorbed = bytearray(cls.cv.curve.params.suite_id)
                absorbed.append(DomSep.PEDERSEN_VRF)
                absorbed.extend(enc_64(1))
                absorbed.extend(enc_point(input_point))
                absorbed.extend(enc_point(proof.output_point))
                absorbed.extend(enc_64(len(ad)))
                absorbed.extend(ad)
                absorbed.extend(enc_point(proof.blinded_pk))
                absorbed.append(DomSep.CHALLENGE)
                absorbed.extend(enc_point(proof.result_point))
                absorbed.extend(enc_point(proof.ok))
                c = dec_scalar_mod(cls.cv, squeeze_transcript_bytes(cls.cv.curve.params.hash_fn, bytes(absorbed), CHALLENGE_LEN))

                batch_items.append((proof, input_point, c))
                coefficient_item_bytes.extend(enc_scalar(cls.cv, c))
                coefficient_item_bytes.extend(enc_scalar(cls.cv, proof.s))
                coefficient_item_bytes.extend(enc_scalar(cls.cv, proof.sb))
        except (AttributeError, TypeError, ValueError):
            return False

        if not batch_items:
            return True

        absorbed = bytearray(cls.cv.curve.params.suite_id)
        absorbed.append(DomSep.BATCH_VERIFY)
        absorbed.extend(coefficient_item_bytes)
        weights = squeeze_transcript_bytes(cls.cv.curve.params.hash_fn, bytes(absorbed), 2 * CHALLENGE_LEN * len(batch_items))

        point_count = len(batch_items) * 5 + 2
        points: list[CurvePoint | None] = [None] * point_count
        scalars = [0] * point_count
        generator_scalar = 0
        blinding_scalar = 0
        pos = 0

        for index, (proof, input_point, c) in enumerate(batch_items):
            offset = 2 * CHALLENGE_LEN * index
            io_weight = dec_scalar_mod(cls.cv, weights[offset : offset + CHALLENGE_LEN])
            commitment_weight = dec_scalar_mod(cls.cv, weights[offset + CHALLENGE_LEN : offset + 2 * CHALLENGE_LEN])

            value = (io_weight * proof.s) % order
            if value > half_order:
                value -= order
            points[pos] = input_point
            scalars[pos] = value
            pos += 1

            value = -(io_weight * c) % order
            if value > half_order:
                value -= order
            points[pos] = proof.output_point
            scalars[pos] = value
            pos += 1

            points[pos] = proof.ok
            scalars[pos] = -io_weight
            pos += 1

            generator_scalar = (generator_scalar + commitment_weight * proof.s) % order
            blinding_scalar = (blinding_scalar + commitment_weight * proof.sb) % order

            value = -(commitment_weight * c) % order
            if value > half_order:
                value -= order
            points[pos] = proof.blinded_pk
            scalars[pos] = value
            pos += 1

            points[pos] = proof.result_point
            scalars[pos] = -commitment_weight
            pos += 1

        if not cls.cv.curve.params.auxiliary_points.blinding_base:
            raise ValueError("Curve does not have a blinding base point for Pedersen VRF")
        blinding_base = cls.cv.point_type(*cls.cv.curve.params.auxiliary_points.blinding_base)

        if generator_scalar:
            value = generator_scalar
            if value > half_order:
                value -= order
            points[pos] = cls.cv.point_type.generator_point()
            scalars[pos] = value
            pos += 1
        if blinding_scalar:
            value = blinding_scalar
            if value > half_order:
                value -= order
            points[pos] = blinding_base
            scalars[pos] = value
            pos += 1

        folded_points = [point for point in points[:pos] if point is not None]
        folded_scalars = scalars[:pos]
        seen: set[int] = set()
        has_duplicate = False
        for point in folded_points:
            point_id = id(point)
            if point_id in seen:
                has_duplicate = True
                break
            seen.add(point_id)

        if has_duplicate:
            points_by_id: dict[int, CurvePoint] = {}
            scalars_by_id: dict[int, int] = {}
            for point, scalar in zip(folded_points, folded_scalars, strict=True):
                scalar %= order
                if scalar == 0:
                    continue
                point_id = id(point)
                if point_id in scalars_by_id:
                    scalars_by_id[point_id] = (scalars_by_id[point_id] + scalar) % order
                else:
                    points_by_id[point_id] = point
                    scalars_by_id[point_id] = scalar

            folded_points = []
            folded_scalars = []
            for point_id, point in points_by_id.items():
                scalar = scalars_by_id[point_id] % order
                if scalar > half_order:
                    scalar -= order
                if scalar:
                    folded_points.append(point)
                    folded_scalars.append(scalar)

        return cls.cv.point_type.msm(folded_points, folded_scalars).is_identity()
