from __future__ import annotations

from abc import abstractmethod
from dataclasses import dataclass
from typing import Protocol, Self, TypeVar, Generic, Final, ClassVar, Union
import hashlib

C = TypeVar("C", bound="CurveProtocol")


class CurveProtocol(Protocol):
    """Protocol defining required curve operations for points."""

    PRIME_FIELD: int
    ORDER: int
    Z: int
    UNCOMPRESSED: bool
    ENDIAN: str
    COFACTOR: int
    SUITE_STRING: bytes


class PointProtocol(Protocol[C]):
    """Protocol defining the interface for curve points."""

    x: int
    y: int
    curve: C

    def __add__(self, other: "PointProtocol[C]") -> "PointProtocol[C]":
        ...

    def __mul__(self, scalar: int) -> "PointProtocol[C]":
        ...

    def is_on_curve(self) -> bool:
        ...
    
    def is_identity(self) -> bool:
        ...


@dataclass(frozen=True)
class Point(Generic[C]):
    """
    Base implementation of an elliptic curve point.

    This class provides the foundation for specific curve point implementations,
    including basic point operations and encoding/decoding functionality.

    Attributes:
        x: x-coordinate
        y: y-coordinate
        curve: The curve this point belongs to
    """

    x: int
    y: int
    curve: C

    # Class constants
    ENCODING_LENGTH: ClassVar[int] = 32

    def __post_init__(self) -> None:
        """Validate point after initialization."""
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
        return (
            0 <= self.x < self.curve.PRIME_FIELD
            and 0 <= self.y < self.curve.PRIME_FIELD
        )

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

        if self.curve.UNCOMPRESSED:
            return self.uncompressed_p2s()

        p = self.curve.PRIME_FIELD
        n_bytes = (p.bit_length() + 7) // 8
        endian = self.curve.ENDIAN
        if endian != 'little' and endian != 'big':
             raise ValueError("Invalid endianness")
        y_bytes = bytearray(self.y.to_bytes(n_bytes, endian))

        # Compute x sign bit
        x_sign_bit = 1 if self.x > (-self.x % p) else 0
        y_bytes[-1] |= x_sign_bit << 7
        return bytes(y_bytes)

    @classmethod
    def string_to_point(cls, octet_string: Union[str, bytes]) -> Self | str:
        """
        Convert compressed octet string back to point.
        Args:
            octet_string: Compressed point bytes

        Returns:
            Point: Decoded point or returns "INVALID" If encoding is invalid
        """

        if cls.curve.UNCOMPRESSED:
            return cls.uncompressed_s2p(octet_string)

        if isinstance(octet_string, str):
            octet_string = bytes.fromhex(octet_string)

        # Extract x sign bit from MSB of last byte
        x_sign_bit = (octet_string[-1] >> 7) & 1

        # Mask out MSB to recover y
        y_bytes = bytearray(octet_string)
        y_bytes[-1] &= 0x7F
        endian = cls.curve.ENDIAN
        if endian != 'little' and endian != 'big':
             raise ValueError("Invalid endianness")
        y = int.from_bytes(y_bytes, endian)
        x_candidates = cls._x_recover(y)

        if x_candidates is None:
            return "INVALID"

        x, neg_x = x_candidates

        # Pick x using x_sign_bit
        chosen_x = neg_x if x_sign_bit else x
        try:
            return cls(chosen_x, y)
        except ValueError:
            return "INVALID"  # Needed for TAI_Case

    def uncompressed_p2s(self) -> bytes:
        p = self.curve.PRIME_FIELD
        byte_length = (p.bit_length() + 7) // 8
        endian = self.curve.ENDIAN
        if endian != 'little' and endian != 'big':
             raise ValueError("Invalid endianness")
        # Encode u and v coordinates as little-endian bytes
        x_bytes = self.x.to_bytes(byte_length, endian)
        y_bytes = self.y.to_bytes(byte_length, endian)
        return x_bytes + y_bytes

    @classmethod
    def uncompressed_s2p(cls, octet_string: Union[str, bytes]) -> "Point[C]":
        if isinstance(octet_string, str):
            octet_string = bytes.fromhex(octet_string)
        p = cls.curve.PRIME_FIELD
        byte_length = (p.bit_length() + 7) // 8
        endian = cls.curve.ENDIAN
        if endian != 'little' and endian != 'big':
             raise ValueError("Invalid endianness")
        # Split into u and v coordinates
        x_bytes = octet_string[:byte_length]
        y_bytes = octet_string[byte_length:]
        x = int.from_bytes(x_bytes, endian)
        y = int.from_bytes(y_bytes, endian)
        # Create the point
        point = cls(x % cls.curve.PRIME_FIELD, y % cls.curve.PRIME_FIELD)
        # Verify the point is on the curve
        if not point.is_on_curve():
            raise ValueError("Point is not on the curve")
        return point

    @classmethod
    def _x_recover(cls, y: int) -> int:
        """
        Recover x-coordinate from y.

        Args:
            y: y-coordinate

        Returns:
            int: Recovered x-coordinate

        Raises:
            ValueError: If x cannot be recovered
        """
        raise NotImplementedError("Must be implemented by subclass")

    @staticmethod
    def _get_bit(data: bytes, bit_index: int) -> int:
        """
        Get specific bit from byte sequence.

        Args:
            data: Byte sequence
            bit_index: Index of bit to retrieve

        Returns:
            int: Bit value (0 or 1)
        """
        byte_index = bit_index // 8
        bit_offset = bit_index % 8
        return (data[byte_index] >> bit_offset) & 1

    @classmethod  # modified
    def encode_to_curve_tai(cls, alpha_string: bytes | str, salt: bytes = b"") -> Self:
        """
        Encode a string to a curve point using try-and-increment method for ECVRF.

        Args:
            alpha: String to encode
            salt: Optional salt for the encoding

        Returns:
            TEAffinePoint: Resulting curve point
        """
        ctr = 0
        H = "INVALID"
        front = b"\x01"
        back = b"\x00"
        alpha_string = (
            alpha_string.encode() if isinstance(alpha_string, str) else alpha_string
        )
        salt = salt.encode() if isinstance(salt, str) else salt
        suite_string = cls.curve.SUITE_STRING
        while H == "INVALID" or H == cls.identity_point():
            ctr_string = ctr.to_bytes(1, "big")
            hash_input = suite_string + front + salt + alpha_string + ctr_string + back
            if cls.__name__ == "P256PointVariant":
                hash_output = hashlib.sha256(hash_input).digest()
                H = cls.string_to_point(b"\x02" + hash_output[:32])
            else:
                hash_output = hashlib.sha512(hash_input).digest()
                H = cls.string_to_point(hash_output[:32])
            if H != "INVALID" and cls.curve.COFACTOR > 1:
                H = H.clear_cofactor()
            ctr += 1
        return H
