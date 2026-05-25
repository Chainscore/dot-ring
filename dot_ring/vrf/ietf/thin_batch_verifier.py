from __future__ import annotations

import secrets
from typing import Any

from dot_ring.curve.curve import CurveVariant
from dot_ring.curve.point import CurvePoint
from dot_ring.vrf.transcript import DomSep, VrfIo, challenge, schnorr_ios, vrf_transcript_scalars

from .thin_batch_item import ThinBatchItem
from .thin_vrf import ThinVRF


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


class ThinBatchVerifier:
    def __init__(self, curve: CurveVariant):
        self.cv = curve
        self.items: list[ThinBatchItem] = []

    @classmethod
    def __class_getitem__(cls, curve_variant: CurveVariant | Any) -> type[ThinBatchVerifier] | Any:
        if not isinstance(curve_variant, CurveVariant):
            return cls

        class _SpecializedThinBatchVerifier(cls):
            def __init__(self) -> None:
                super().__init__(curve_variant)

        _SpecializedThinBatchVerifier.__name__ = f"{cls.__name__}[{curve_variant.name}]"
        return _SpecializedThinBatchVerifier

    def push(self, public_key: CurvePoint, ios: list[VrfIo], additional_data: bytes, proof: ThinVRF) -> None:
        chained_ios = schnorr_ios(self.cv, public_key, ios)
        transcript, scalar_stream = vrf_transcript_scalars(self.cv, DomSep.THIN_VRF, chained_ios, additional_data)
        c = challenge(self.cv, [proof.r], transcript)
        self.items.append(ThinBatchItem(c, chained_ios, scalar_stream.take(len(chained_ios)), proof.r, proof.s))

    def verify(self) -> bool:
        if not self.items:
            return True

        points: list[CurvePoint] = []
        scalars: list[int] = []
        for coefficient, item in zip(_batch_coefficients(len(self.items), self.cv.curve.ORDER), self.items, strict=False):
            weighted_c = coefficient * item.c
            weighted_s = coefficient * item.s

            for io, z in zip(item.ios, item.zs, strict=True):
                points.extend([io.input, io.output])
                scalars.extend([weighted_s * z, -(weighted_c * z)])
            points.append(item.r)
            scalars.append(-coefficient)
        return self.cv.point.msm(points, scalars).is_identity()
