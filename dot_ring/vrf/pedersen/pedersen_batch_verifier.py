from __future__ import annotations

import secrets
from typing import Any

from dot_ring.curve.curve import CurveVariant
from dot_ring.curve.point import CurvePoint
from dot_ring.vrf.transcript import DomSep, VrfIo, challenge, vrf_transcript_scalars

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
        transcript, scalar_stream = vrf_transcript_scalars(self.cv, DomSep.PEDERSEN_VRF, ios, additional_data)
        transcript.absorb_point(proof.blinded_pk)
        c = challenge(self.cv, [proof.result_point, proof.ok], transcript)
        self.items.append(
            PedersenBatchItem(
                c=c,
                ios=list(ios),
                zs=scalar_stream.take(len(ios)),
                pk_com=proof.blinded_pk,
                r=proof.result_point,
                ok=proof.ok,
                s=proof.s,
                sb=proof.sb,
            )
        )

    def verify(self) -> bool:
        if not self.items:
            return True

        blinding_base = _blinding_base(self.cv)
        generator = self.cv.point.generator_point()
        points: list[CurvePoint] = []
        scalars: list[int] = []
        coefficients = _batch_coefficients(2 * len(self.items), self.cv.curve.ORDER)

        for index, item in enumerate(self.items):
            io_weight = coefficients[2 * index]
            commitment_weight = coefficients[2 * index + 1]

            for io, z in zip(item.ios, item.zs, strict=True):
                points.extend([io.input, io.output])
                scalars.extend([io_weight * item.s * z, -(io_weight * item.c * z)])
            points.append(item.ok)
            scalars.append(-io_weight)

            points.extend([generator, blinding_base, item.pk_com, item.r])
            scalars.extend(
                [
                    commitment_weight * item.s,
                    commitment_weight * item.sb,
                    -(commitment_weight * item.c),
                    -commitment_weight,
                ]
            )

        return self.cv.point.msm(points, scalars).is_identity()
