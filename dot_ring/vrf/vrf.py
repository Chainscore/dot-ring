from __future__ import annotations

from typing import Any, ClassVar, Generic, Self, TypeVar

from ..curve.curve import CurveVariant

C = TypeVar("C", bound=CurveVariant)


class VRF(Generic[C]):
    """
    Base VRF (Verifiable Random Function) implementation.

    This class provides the core functionality for VRF operations,
    following the shared dot-ring VRF interface.

    Usage with subscript syntax:
        >>> from dot_ring.curve.specs.bandersnatch import Bandersnatch
        >>> from dot_ring.vrf.ietf import TinyVRF
        >>> proof = TinyVRF[Bandersnatch].prove(alpha, secret_key, additional_data)
    """

    cv: ClassVar[CurveVariant]

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
