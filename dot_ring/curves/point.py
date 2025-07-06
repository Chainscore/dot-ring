from __future__ import annotations

from abc import abstractmethod
from dataclasses import dataclass
# pyright: reportGeneralTypeIssues=false
from typing import Protocol, Self, TypeVar, Generic, Final, ClassVar, Union, overload

C = TypeVar("C", bound="CurveProtocol")


class CurveProtocol(Protocol):
    @property
    def PRIME_FIELD(self) -> int: ...

    @property
    def ORDER(self) -> int: ...

    @property
    def Z(self) -> int: ...


class PointProtocol(Protocol[C]):
    x: int
    y: int
    curve: C

    def __add__(self, other: "PointProtocol[C]") -> Self: ...

    def __mul__(self, scalar: int) -> Self: ...

    def is_on_curve(self) -> bool: ...


@dataclass(frozen=True)
class Point(Generic[C]):
    x: Final[int]
    y: Final[int]
    curve: Final[C]

    ENCODING_LENGTH: ClassVar[int] = 32

    # ------------------------------------------------------------------
    # Minimal algebra interface – subclasses override fast versions
    # ------------------------------------------------------------------

    def __add__(self, other: "Point[C]") -> "Point[C]":  # noqa: D401
        """Point addition (must be implemented by subclass)."""
        raise NotImplementedError

    def __neg__(self) -> "Point[C]":  # noqa: D401
        raise NotImplementedError

    def __sub__(self, other: "Point[C]") -> "Point[C]":  # noqa: D401
        return self.__add__(-other)  # type: ignore[arg-type]

    @overload
    def __mul__(self, k: int) -> "Point[C]":  # noqa: D401
        """Double-and-add fallback; override for efficient methods."""
        ...

    @overload
    def __mul__(self, k: int) -> "Point[C]":  # noqa: D401
        """Double-and-add fallback; override for efficient methods."""
        ...

    __rmul__ = __mul__  # allows int * Point

    # These must be supplied by concrete subclasses -------------------

    @classmethod
    def identity_point(cls) -> "Point[C]":
        raise NotImplementedError

    def double(self) -> "Point[C]":
        raise NotImplementedError

    def _validate_coordinates(self) -> bool:
        return 0 <= self.x < self.curve.PRIME_FIELD and 0 <= self.y < self.curve.PRIME_FIELD

    @abstractmethod
    def is_on_curve(self) -> bool:
        raise NotImplementedError

    # ---------------------------------------------------------------------
    # Encoding helpers
    # ---------------------------------------------------------------------

    def point_to_string(self) -> bytes:
        p = self.curve.PRIME_FIELD
        p_half = (p - 1) // 2
        x, y = self.x, self.y
        y_bytes = bytearray(int(y).to_bytes(32, "little"))
        x_sign_bit = 1 if x >= p_half else 0
        y_bytes[-1] |= x_sign_bit << 7
        return bytes(y_bytes)

    @classmethod
    def string_to_point(cls, octet_string: Union[str, bytes]) -> Self:
        if isinstance(octet_string, str):
            octet_string = bytes.fromhex(octet_string)

        y = int.from_bytes(octet_string, "little") & ((1 << 255) - 1)
        x = cls._x_recover(y)
        x_parity = octet_string[-1] >> 7
        p_half = (cls.curve.PRIME_FIELD - 1) // 2  # type: ignore[attr-defined]
        if (x < p_half) == x_parity:
            x = cls.curve.PRIME_FIELD - x  # type: ignore[attr-defined]
        return cls(x % cls.curve.PRIME_FIELD, y % cls.curve.PRIME_FIELD)  # type: ignore[attr-defined,call-arg]

    def to_bytes(self) -> bytes:
        return self.point_to_string()

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        return cls.string_to_point(data)

    @classmethod
    def _x_recover(cls, y: int) -> int:
        raise NotImplementedError

    @staticmethod
    def _get_bit(data: bytes, bit_index: int) -> int:
        byte_index = bit_index // 8
        bit_offset = bit_index % 8
        return (data[byte_index] >> bit_offset) & 1