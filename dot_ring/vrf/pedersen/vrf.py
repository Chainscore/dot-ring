"""Pedersen VRF (section 4).

The library proof envelope is `gamma || Y_bar || R || O_k || s || s_b`;
the spec proof is `Y_bar || R || O_k || s || s_b`.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, TypeVar

from dot_ring.curve.curve import CurveVariant
from dot_ring.curve.point import CurvePoint
from dot_ring.vrf.codec import dec_point, dec_scalar, dec_scalar_mod, enc_point, enc_scalar, point_len, scalar_len
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
            output_point = dec_point(cls.cv, proof[0:point_length])
            public_key_cp = dec_point(cls.cv, proof[point_length : 2 * point_length])
            r = dec_point(cls.cv, proof[2 * point_length : 3 * point_length])
            ok = dec_point(cls.cv, proof[3 * point_length : 4 * point_length])
        except ValueError as exc:
            raise ValueError("Invalid point in proof") from exc
        s = dec_scalar(cls.cv, proof[4 * point_length : 4 * point_length + scalar_size])
        sb = dec_scalar(cls.cv, proof[4 * point_length + scalar_size :])

        return cls(
            output_point=output_point,
            blinded_pk=public_key_cp,
            result_point=r,
            ok=ok,
            s=s,
            sb=sb,
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
        )

    def verify(self, input: bytes, additional_data: bytes, salt: bytes = b"") -> bool:
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

    def verify_unblinding(self, public_key: bytes, blinding_factor: int) -> bool:
        """Spec section 4.3: check `Y_bar = Y + b*B` for a revealed blinding factor."""
        order = self.cv.curve.params.subgroup_order
        if not 0 <= blinding_factor < order:
            return False

        public = dec_point(self.cv, public_key)
        if not self.cv.curve.params.auxiliary_points.blinding_base:
            raise ValueError("Curve does not have a blinding base point for Pedersen VRF")
        blinding_base = self.cv.point(self.cv.curve.params.auxiliary_points.blinding_base)

        return public + blinding_base * blinding_factor == self.blinded_pk

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
    def batch_verify(
        cls,
        proofs: Sequence[PedersenVRF],
        inputs: Sequence[bytes],
        additional_data: Sequence[bytes],
        salts: Sequence[bytes] | None = None,
    ) -> bool:
        if salts is None:
            salts = [b""] * len(proofs)

        order = cls.cv.curve.params.subgroup_order
        half_order = order >> 1
        batch_items: list[tuple[PedersenVRF, CurvePoint, int]] = []
        coefficient_item_bytes = bytearray()

        try:
            for proof, input_value, ad, salt in zip(proofs, inputs, additional_data, salts, strict=True):
                input_point = cls.cv.point_type.encode_to_curve(input_value, salt)
                transcript, _ = vrf_transcript(cls.cv, DomSep.PEDERSEN_VRF, [VrfIo(input_point, proof.output_point)], ad)
                transcript.absorb(enc_point(proof.blinded_pk))
                c = challenge(cls.cv, [proof.result_point, proof.ok], transcript)

                batch_items.append((proof, input_point, c))
                coefficient_item_bytes.extend(enc_scalar(cls.cv, c))
                coefficient_item_bytes.extend(enc_scalar(cls.cv, proof.s))
                coefficient_item_bytes.extend(enc_scalar(cls.cv, proof.sb))
        except (AttributeError, TypeError, ValueError):
            return False

        if not batch_items:
            return True

        if not cls.cv.curve.params.auxiliary_points.blinding_base:
            raise ValueError("Curve does not have a blinding base point for Pedersen VRF")
        blinding_base = cls.cv.point_type(*cls.cv.curve.params.auxiliary_points.blinding_base)

        def signed(scalar: int) -> int:
            scalar %= order
            return scalar - order if scalar > half_order else scalar

        absorbed = bytearray(cls.cv.curve.params.suite_id)
        absorbed.append(DomSep.BATCH_VERIFY)
        absorbed.extend(coefficient_item_bytes)
        weights = squeeze_transcript_bytes(cls.cv.curve.params.hash_fn, bytes(absorbed), 2 * CHALLENGE_LEN * len(batch_items))

        points: list[CurvePoint] = []
        scalars: list[int] = []
        generator_scalar = 0
        blinding_scalar = 0

        for index, (proof, input_point, c) in enumerate(batch_items):
            offset = 2 * CHALLENGE_LEN * index
            io_weight = dec_scalar_mod(cls.cv, weights[offset : offset + CHALLENGE_LEN])
            commitment_weight = dec_scalar_mod(cls.cv, weights[offset + CHALLENGE_LEN : offset + 2 * CHALLENGE_LEN])

            points.extend((proof.ok, proof.output_point, input_point))
            scalars.extend((io_weight, signed(io_weight * c), signed(-io_weight * proof.s)))

            generator_scalar = (generator_scalar - commitment_weight * proof.s) % order
            blinding_scalar = (blinding_scalar - commitment_weight * proof.sb) % order

            points.extend((proof.result_point, proof.blinded_pk))
            scalars.extend((commitment_weight, signed(commitment_weight * c)))

        if generator_scalar:
            points.append(cls.cv.point_type.generator_point())
            scalars.append(signed(generator_scalar))
        if blinding_scalar:
            points.append(blinding_base)
            scalars.append(signed(blinding_scalar))

        return cls.cv.point_type.msm(points, scalars).is_identity()
