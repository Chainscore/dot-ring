from __future__ import annotations

from abc import abstractmethod
from typing import TYPE_CHECKING, Generic, Self, TypeVar

from dot_ring.curve.e2c import E2C_Variant
from dot_ring.curve.fp2 import Fp2

if TYPE_CHECKING:
    from dot_ring.curve.curve import Curve

# TypeVar for curve types
Coord = int | Fp2
CoordT = TypeVar("CoordT", int, Fp2)


C = TypeVar("C", bound="Curve[Coord]")


class CurvePoint(Generic[C, CoordT]):
    """
    Base implementation of an elliptic curve point.

    This class provides the foundation for specific curve point implementations,
    including basic point operations and encoding/decoding functionality.

    Attributes:
        x: x-coordinate
        y: y-coordinate
        curve: The curve this point belongs to
    """

    x: CoordT | None
    y: CoordT | None
    curve: C

    def __init__(
        self,
        x: CoordT | None,
        y: CoordT | None,
    ) -> None:
        self.x = x
        self.y = y
        self.curve = self.__class__.curve
        super().__init__()
        self.__post_init__()

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, CurvePoint):
            return NotImplemented
        return self.x == other.x and self.y == other.y and self.curve is other.curve

    def __add__(self, other: Self) -> Self:
        raise NotImplementedError

    def __sub__(self, other: Self) -> Self:
        raise NotImplementedError

    def __mul__(self, scalar: int) -> Self:
        raise NotImplementedError

    def __rmul__(self, scalar: int) -> Self:
        return self.__mul__(scalar)

    def __post_init__(self) -> None:
        """Validate point after initialization."""
        if self.is_identity():
            return
        if not self._validate_coordinates():
            raise ValueError("Invalid point coordinates")
        if not self.is_on_curve():
            raise ValueError("Point is not on the curve")

    def _validate_coordinates(self) -> bool:
        """
        Validate point coordinates are within field bounds.

        Returns:
            bool: True if coordinates are valid
        """
        if self.is_identity():
            return True
        field_modulus = self.curve.params.field_modulus
        return 0 <= self.x < field_modulus and 0 <= self.y < field_modulus

    @classmethod
    def msm(cls, points: list[Self], scalars: list[int]) -> Self:
        """
        Compute sum(P_i * s_i) for pairs (P_i, s_i).
        Default implementation uses naive summation.
        Subclasses can override with optimized algorithms (e.g. Pippenger, GLV).
        """
        if len(points) != len(scalars):
            raise ValueError("Points and scalars must have same length")

        if not points:
            return cls.identity()

        result = cls.identity()
        for point, scalar in zip(points, scalars, strict=False):
            result = result + (point * scalar)

        return result

    @classmethod
    def generator_point(cls) -> Self:
        """
        Get the generator point of the curve.

        Returns:
            BandersnatchPoint: Generator point
        """
        generator_x, generator_y = cls.curve.params.generator
        return cls(generator_x, generator_y)

    @abstractmethod
    def is_on_curve(self) -> bool:
        """
        Check if the point lies on the curve.

        Returns:
            bool: True if point is on curve

        Raises:
            NotImplementedError: Must be implemented by subclass
        """
        raise NotImplementedError("Must be implemented by subclass")

    @abstractmethod
    def is_identity(self) -> bool:
        """
        Check if this is the identity element.

        Returns:
            bool: True if this is the identity element
        """
        raise NotImplementedError("Must be implemented by subclass")

    @classmethod
    @abstractmethod
    def identity(cls) -> Self:
        """
        Get the identity element.

        Returns:
            Self: Identity element
        """
        raise NotImplementedError("Must be implemented by subclass")

    def point_to_string(self) -> bytes:
        """
        Convert elliptic curve point (x, y) to compressed octet string.
        - The y-coordinate is encoded as 32 bytes.
        - The most significant bit of the last byte indicates the sign of the x-coordinate.

        Args:
            self: The point (x, y) to convert

        Returns:
            bytes: The compressed point representation
        """

        if self.curve.params.encoding.uncompressed:
            encoded = self.uncompressed_p2s()
            return encoded

        p = self.curve.params.field_modulus
        n_bytes = (p.bit_length() + 7) // 8
        y_bytes = bytearray(self.y.to_bytes(n_bytes, self.curve.params.encoding.endian))

        # Compute x sign bit
        x_sign_bit = 1 if self.x > -self.x % p else 0
        y_bytes[-1] |= x_sign_bit << 7
        encoded = bytes(y_bytes)
        return encoded

    @classmethod
    def string_to_point(cls, octet_string: bytes) -> Self:
        """
        Convert compressed octet string back to point.
        Args:
            octet_string: Compressed point bytes

        Returns:
            Point: Decoded point

        Raises:
            ValueError: If encoding is invalid.
        """

        if not octet_string:
            raise ValueError("Empty octet string")

        if cls.curve.params.encoding.uncompressed:
            return cls.uncompressed_s2p(octet_string)

        x_sign_bit = (octet_string[-1] >> 7) & 1
        y_bytes = bytearray(octet_string)
        y_bytes[-1] &= 0x7F
        y = int.from_bytes(y_bytes, cls.curve.params.encoding.endian)
        if y >= cls.curve.params.field_modulus:
            raise ValueError("Invalid point encoding")

        x_candidates = cls._x_recover(y)
        if x_candidates is None:
            raise ValueError("Invalid point encoding")

        if isinstance(x_candidates, int):
            x, neg_x = x_candidates, (-x_candidates) % cls.curve.params.field_modulus
        else:
            x, neg_x = x_candidates

        x, y = neg_x if x_sign_bit else x, y
        return cls(x, y)

    def uncompressed_p2s(self) -> bytes:
        p = self.curve.params.field_modulus
        byte_length = (p.bit_length() + 7) // 8
        # Encode u and v coordinates as little-endian bytes
        x_bytes = self.x.to_bytes(byte_length, self.curve.params.encoding.endian)
        y_bytes = self.y.to_bytes(byte_length, self.curve.params.encoding.endian)
        return x_bytes + y_bytes

    @classmethod
    def uncompressed_s2p(cls, octet_string: bytes) -> Self:
        curve = cls.curve
        p = curve.params.field_modulus
        byte_length = (p.bit_length() + 7) // 8
        # Split into u and v coordinates
        x = int.from_bytes(octet_string[:byte_length], curve.params.encoding.endian)
        y = int.from_bytes(octet_string[byte_length:], curve.params.encoding.endian)
        # Create the point
        return cls(x, y)

    @classmethod
    def _x_recover(cls, y: int) -> int | tuple[int, int] | None:
        """
        Recover x-coordinate from y.

        Args:
            y: y-coordinate

        Returns:
            int | tuple[int, int] | None: Recovered x candidate(s)

        Raises:
            ValueError: If x cannot be recovered
        """
        raise NotImplementedError("Must be implemented by subclass")

    @classmethod
    def encode_to_curve(
        cls,
        alpha_string: bytes,
        salt: bytes = b"",
    ) -> Self:
        curve = cls.curve
        if curve.e2c_variant != E2C_Variant.TAI:
            raise ValueError(f"Unexpected E2C Variant: {curve.e2c_variant}")

        from dot_ring.vrf.codec import enc_64
        from dot_ring.vrf.domain import DomSep
        from dot_ring.vrf.primitives import VrfTranscript

        data = salt + alpha_string
        field_len = (curve.params.field_modulus.bit_length() + 7) // 8

        prefix = VrfTranscript(curve.params.suite_id, curve.params.hash_fn)
        prefix.absorb(bytes([DomSep.HASH_TO_CURVE]))
        prefix.absorb(enc_64(len(data)))
        prefix.absorb(data)

        for counter in range(256):
            t = prefix.copy()
            t.absorb(bytes([counter]))
            candidate = bytearray(t.squeeze(field_len))
            if hasattr(curve.params, "a") and hasattr(curve.params, "b"):
                shave = field_len * 8 - curve.params.field_modulus.bit_length()
                if shave:
                    candidate[-1] &= (1 << (8 - shave)) - 1
                candidate = bytearray(candidate + b"\x80")
            else:
                sign = candidate[-1] & 0x80
                shave = field_len * 8 - curve.params.field_modulus.bit_length()
                if shave:
                    candidate[-1] &= (1 << (8 - shave)) - 1
                candidate[-1] |= sign
            try:
                point = cls.string_to_point(bytes(candidate))
            except ValueError:
                continue
            if point.curve.params.cofactor > 1:
                point = point * point.curve.params.cofactor
            if not point.is_identity():
                return point
        raise ValueError("hash_to_curve_tai failed")

    def __hash__(self) -> int:
        if self.x is None or self.y is None:
            return 0
        if isinstance(self.x, int) and isinstance(self.y, int):
            x_val = self.x
            y_val = self.y
        elif isinstance(self.x, Fp2) and isinstance(self.y, Fp2):
            x_val = self.x.re + self.x.im
            y_val = self.y.re + self.y.im
        else:
            raise TypeError(f"Unsupported point coordinate type: {type(self.y).__name__}")

        return (x_val + y_val) % self.curve.params.subgroup_order
