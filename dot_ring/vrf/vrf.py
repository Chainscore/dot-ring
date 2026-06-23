from __future__ import annotations

from typing import Any, ClassVar, Generic, Self, TypeVar

from ..curve.curve import CurveVariant

C = TypeVar("C", bound=CurveVariant)


class VRF(Generic[C]):
    """Base VRF class that specializes implementations by curve variant."""

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

    @classmethod
    def prove(cls, alpha: bytes, secret_key: bytes, additional_data: bytes, salt: bytes, **_kwargs: Any) -> Self:
        raise NotImplementedError(f"{cls.__name__} does not implement prove")

    def verify(self, *_args: Any, **_kwargs: Any) -> bool:
        raise NotImplementedError(f"{self.__class__.__name__} does not implement verify")

    def encode(self) -> bytes:
        raise NotImplementedError(f"{self.__class__.__name__} does not implement encode")

    @classmethod
    def decode(cls, data: bytes) -> Self:
        raise NotImplementedError(f"{cls.__name__} does not implement from_bytes")

    @classmethod
    def batch_verify(cls, *_args: Any, **_kwargs: Any) -> bool:
        raise NotImplementedError(f"{cls.__name__} does not implement batch_verify")
