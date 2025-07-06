from __future__ import annotations

from abc import abstractmethod
from dataclasses import dataclass
# pyright: reportGeneralTypeIssues=false
from typing import Any, Protocol, TypeVar, Generic, Final, ClassVar, Union, overload, cast

CurveT = TypeVar("CurveT", bound="CurveProtocol")
TP = TypeVar("TP", bound="Point[Any]")  # concrete point subtype


class CurveProtocol(Protocol):
    @property
    def PRIME_FIELD(self) -> int: ...

    @property
    def ORDER(self) -> int: ...

    @property
    def Z(self) -> int: ...


class PointProtocol(Protocol[CurveT]):
    x: int
    y: int
    curve: CurveT

    def __add__(self, other: "PointProtocol[CurveT]") -> TP: ...

    def __mul__(self, scalar: int) -> TP: ...

    def is_on_curve(self) -> bool: ...


@dataclass(frozen=True)
class Point(Generic[CurveT]):
    x: Final[int]
    y: Final[int]
    curve: Final[CurveT]

    ENCODING_LENGTH: ClassVar[int] = 32

    # ------------------------------------------------------------------
    # Minimal algebra interface – subclasses override fast versions
    # ------------------------------------------------------------------

    def __add__(self: TP, other: TP) -> TP:  # noqa: D401
        """Point addition (must be implemented by subclass)."""
        raise NotImplementedError

    def __neg__(self) -> TP:  # noqa: D401
        raise NotImplementedError

    def __sub__(self: TP, other: TP) -> TP:  # noqa: D401
        return self.__add__(cast(TP, -other))

    @overload
    def __mul__(self: TP, k: int) -> TP: ...

    def __mul__(self: TP, k: int) -> TP:  # noqa: D401
        """Support scalar multiplication and fallback * as addition."""
        if not isinstance(k, int):
            raise TypeError("Scalar multiplier must be int")

        res: TP = cast(TP, self.identity_point())
        addend: TP = cast(TP, self)
        n = k
        while n:
            if n & 1:
                res = res.__add__(addend)
            addend = cast(TP, addend.double())
            n >>= 1
        return res

    def __rmul__(self: TP, k: int) -> TP:  # enable int * Point
        return self.__mul__(k)

    # These must be supplied by concrete subclasses -------------------

    @classmethod
    def identity_point(cls: type[TP]) -> TP:
        raise NotImplementedError

    def double(self: TP) -> TP:
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
    def string_to_point(cls, octet_string: Union[str, bytes]) -> TP:
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
    def from_bytes(cls, data: bytes) -> TP:
        return cls.string_to_point(data)

    @classmethod
    def _x_recover(cls, y: int) -> int:
        raise NotImplementedError

    @staticmethod
    def _get_bit(data: bytes, bit_index: int) -> int:
        byte_index = bit_index // 8
        bit_offset = bit_index % 8
        return (data[byte_index] >> bit_offset) & 1