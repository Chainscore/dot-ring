from __future__ import annotations

from dataclasses import dataclass
from typing import Any, ClassVar, Generic, Self, TypeVar, cast

from ..curve.curve import CurveVariant
from ..curve.point import CurvePoint

C = TypeVar("C", bound=CurveVariant)


@dataclass(frozen=True, slots=True)
class PreparedSecretKey(Generic[C]):
    """Decoded VRF secret scalar with its matching public key."""

    curve: CurveVariant
    secret_scalar: int
    public_key: CurvePoint
    public_key_bytes: bytes


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

    @classmethod
    def get_public_key(cls, secret_key: bytes) -> bytes:
        """Take the Secret_Key and return Public Key"""
        return cls.prepare_secret_key(secret_key).public_key_bytes

    @classmethod
    def prepare_secret_key(cls, secret_key: bytes) -> PreparedSecretKey[C]:
        """Decode a secret key once and compute its matching public key."""
        from dot_ring.vrf.transcript import scalar_decode

        secret_key_int = scalar_decode(cls.cv, secret_key)
        generator = cls.cv.generator_point()
        public_key: CurvePoint = cast(Any, generator) * secret_key_int
        return PreparedSecretKey(
            curve=cls.cv,
            secret_scalar=secret_key_int,
            public_key=public_key,
            public_key_bytes=public_key.point_to_string(),
        )
