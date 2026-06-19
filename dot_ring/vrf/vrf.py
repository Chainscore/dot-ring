from __future__ import annotations

from functools import lru_cache
from typing import Any, ClassVar, Generic, Self, TypeVar

from ..curve.curve import CurveVariant
from ..curve.point import CurvePoint
from ..curve.twisted_edwards.te_affine_point import TEAffinePoint

C = TypeVar("C", bound=CurveVariant)


@lru_cache(maxsize=32)
def _cofactor_inverse(cofactor: int, subgroup_order: int) -> int:
    return pow(cofactor, -1, subgroup_order)


class VRF(Generic[C]):
    """Base VRF class that specializes implementations by curve variant."""

    cv: ClassVar[CurveVariant]

    @staticmethod
    def _valid_point(point: CurvePoint) -> bool:
        """Verifier-side `dec_point`: nonidentity and in the prime-order subgroup."""
        if point.is_identity():
            return False

        cofactor = point.curve.params.cofactor
        if cofactor == 1:
            return True

        cofactor_inv = _cofactor_inverse(cofactor, point.curve.params.subgroup_order)
        if isinstance(point, TEAffinePoint):
            cleared = TEAffinePoint.__mul__(point, cofactor)
        else:
            cleared = point * cofactor
        if cleared.is_identity():
            return False
        return cleared * cofactor_inv == point

    def __class_getitem__(cls, curve_variant: CurveVariant | Any) -> type[Self] | Any:
        """
        Create a specialized VRF class for a specific curve variant.

        Args:
            curve_variant: The CurveVariant to specialize for

        Returns:
            A new class with cv set to the curve variant, or cls if generic
        """
        if not isinstance(curve_variant, CurveVariant):
            return cls
        new_class = type(f"{cls.__name__}[{curve_variant.name}]", (cls,), {"cv": curve_variant})
        return new_class
