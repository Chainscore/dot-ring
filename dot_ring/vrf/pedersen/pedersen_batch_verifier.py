from __future__ import annotations

import secrets
from typing import Any

from dot_ring.curve.curve import CurveVariant
from dot_ring.curve.point import CurvePoint
from dot_ring.vrf.transcript import DomSep, VrfIo, challenge, vrf_transcript

from .pedersen_batch_item import PedersenBatchItem
from .pedersen_vrf import PedersenVRF, _blinding_base


def _batch_coefficients(count: int, order: int) -> list[int]:
    if count == 0:
        return []
    coefficients = [1]
    for _ in range(count - 1):
        coefficient = 0
        while coefficient == 0:
            coefficient = secrets.randbelow(order)
        coefficients.append(coefficient)
    return coefficients


class PedersenBatchVerifier:
    def __init__(self, curve: CurveVariant):
        self.cv = curve
        self.items: list[PedersenBatchItem] = []

    @classmethod
    def __class_getitem__(cls, curve_variant: CurveVariant | Any) -> type[PedersenBatchVerifier] | Any:
        if not isinstance(curve_variant, CurveVariant):
            return cls

        class _SpecializedPedersenBatchVerifier(cls):
            def __init__(self) -> None:
                super().__init__(curve_variant)

        _SpecializedPedersenBatchVerifier.__name__ = f"{cls.__name__}[{curve_variant.name}]"
        return _SpecializedPedersenBatchVerifier

    def push(self, ios: list[VrfIo], additional_data: bytes, proof: PedersenVRF) -> None:
        transcript, merged = vrf_transcript(self.cv, DomSep.PEDERSEN_VRF, ios, additional_data)
        transcript.absorb_point(proof.blinded_pk)
        c = challenge(self.cv, [proof.result_point, proof.ok], transcript)
        self.items.append(
            PedersenBatchItem(
                c=c,
                input=merged.input,
                output=merged.output,
                pk_com=proof.blinded_pk,
                r=proof.result_point,
                ok=proof.ok,
                s=proof.s,
                sb=proof.sb,
            )
        )

    def verify(self) -> bool:
        blinding_base = _blinding_base(self.cv)
        generator = self.cv.point.generator_point()
        input_points: list[CurvePoint] = []
        input_scalars: list[int] = []
        commitment_points: list[CurvePoint] = []
        commitment_scalars: list[int] = []
        for coefficient, item in zip(_batch_coefficients(len(self.items), self.cv.curve.ORDER), self.items, strict=False):
            input_points.extend([item.input, item.output, item.ok])
            input_scalars.extend([coefficient * item.s, -coefficient * item.c, -coefficient])
            commitment_points.extend([generator, blinding_base, item.pk_com, item.r])
            commitment_scalars.extend([coefficient * item.s, coefficient * item.sb, -coefficient * item.c, -coefficient])
        return self.cv.point.msm(input_points, input_scalars).is_identity() and self.cv.point.msm(
            commitment_points,
            commitment_scalars,
        ).is_identity()
