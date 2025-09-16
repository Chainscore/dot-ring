from __future__ import annotations

from abc import abstractmethod
from dataclasses import dataclass
from typing import Protocol, Self, TypeVar, Generic, Final, ClassVar, Union

C = TypeVar('C', bound='CurveProtocol')


class CurveProtocol(Protocol):
    """Protocol defining required curve operations for points."""
    PRIME_FIELD: int
    ORDER: int
    Z: int


class PointProtocol(Protocol[C]):
    """Protocol defining the interface for curve points."""
    x: int
    y: int
    curve: C

    def __add__(self, other: 'PointProtocol[C]') -> 'PointProtocol[C]': ...

    def __mul__(self, scalar: int) -> 'PointProtocol[C]': ...

    def is_on_curve(self) -> bool: ...


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
    x: Final[int]
    y: Final[int]
    curve: Final[C]

    # Class constants
    ENCODING_LENGTH: ClassVar[int] = 32  # Default encoding length for most curves

    def __post_init__(self) -> None:
        """Validate point after initialization."""
        if not self._validate_coordinates():
            raise ValueError("Invalid point coordinates")
        if not self.is_on_curve():
            raise ValueError("Point is not on the curve")

    def _validate_coordinates(self) -> bool:
        """
        Validate point coordinates are within field bounds.
        
        The point at infinity is represented with x=None and y=None.

        Returns:
            bool: True if coordinates are valid
        """
        # Handle point at infinity (identity element)
        if self.x is None and self.y is None:
            return True
            
        # Check if coordinates are within field bounds
        return (
            self.x is not None and self.y is not None and
            0 <= self.x < self.curve.PRIME_FIELD and
            0 <= self.y < self.curve.PRIME_FIELD
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

    def point_to_string(self) -> bytes:
        """
        Convert elliptic curve point (x, y) to compressed octet string.
        - The y-coordinate is encoded in little-endian format
        - The most significant bit of the last byte indicates the sign of the x-coordinate.

        The encoding length is determined by the curve's ENCODING_LENGTH attribute
        or calculated from the field size if not specified.

        Args:
            self: The point (x, y) to convert

        Returns:
            bytes: The compressed point representation
        """
        p = self.curve.PRIME_FIELD
        p_half = (p - 1) // 2
        x, y = self.x, self.y
        
        # Get encoding length from curve or calculate from field size
        byte_length = getattr(self.curve, 'ENCODING_LENGTH', (p.bit_length() + 7) // 8)
        y_bytes = bytearray(int(y).to_bytes(byte_length, "little"))
        
        # Set sign bit based on x coordinate
        x_sign_bit = 1 if x >= p_half else 0
        if y_bytes:  # Ensure we have bytes to modify
            y_bytes[-1] |= (x_sign_bit << 7)
            
        return bytes(y_bytes)

    @classmethod
    def string_to_point(cls, octet_string: Union[str, bytes]) -> 'Point[C]':
        """
        Convert compressed octet string back to point.

        Args:
            octet_string: Compressed point bytes or hex string

        Returns:
            Point: Decoded point

        Raises:
            ValueError: If encoding is invalid or point is not on curve
        """
        if isinstance(octet_string, str):  # Convert hex string to bytes
            octet_string = bytes.fromhex(octet_string)

        p = cls.curve.PRIME_FIELD
        
        # Get expected length from curve or calculate from field size
        expected_length = getattr(cls.curve, 'ENCODING_LENGTH', (p.bit_length() + 7) // 8)
        
        if len(octet_string) != expected_length:
            raise ValueError(
                f"Invalid point encoding length. Expected {expected_length} bytes, "
                f"got {len(octet_string)}"
            )

        # Calculate mask for y (all bits except the sign bit)
        y_mask = (1 << (expected_length * 8 - 1)) - 1
        y = int.from_bytes(octet_string, 'little') & y_mask

        # Recover x-coordinate
        x = cls._x_recover(y)
        if x is None:
            raise ValueError("Invalid point: x-coordinate recovery failed")

        # Get the sign bit from the encoded point
        sign_bit = (octet_string[-1] >> 7) & 1
        
        # For Ed448, the sign bit is the LSB of x (not the sign of x)
        if hasattr(cls.curve, 'EDWARDS_A') and hasattr(cls.curve, 'EDWARDS_D'):
            if (x & 1) != sign_bit:
                x = p - x  # Flip x if the LSB doesn't match the sign bit
        else:
            # For other curves, use the original behavior (comparing x to p_half)
            p_half = (p - 1) // 2
            x_parity = 1 if x >= p_half else 0
            if x_parity != sign_bit:
                x = p - x

        # Create and validate the point
        point = cls(x % p, y % p)
        if not point.is_on_curve():
            raise ValueError("Decoded point is not on the curve")
            
        return point

    def to_bytes(self) -> bytes:
        """
        Convert point to compressed byte representation.

        Returns:
            bytes: Compressed point representation
        """
        return self.point_to_string()

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        """
        Create point from compressed byte representation.

        Args:
            data: Compressed point bytes

        Returns:
            BandersnatchPoint: Decoded point

        Raises:
            ValueError: If data is invalid
        """
        return cls.string_to_point(data)

    @classmethod
    def _x_recover(cls, y: int) -> int:
        """
        Recover x-coordinate from y.
        
        This implementation handles both Twisted Edwards and Weierstrass curves.
        For Twisted Edwards curves: ax² + y² = 1 + dx²y²
        
        Args:
            y: y-coordinate

        Returns:
            int: Recovered x-coordinate or None if invalid

        Raises:
            ValueError: If x cannot be recovered
        """
        curve = cls.curve
        p = curve.PRIME_FIELD
        y_sq = (y * y) % p
        
        # Handle Twisted Edwards curves (including Ed448)
        if hasattr(curve, 'EDWARDS_A') and hasattr(curve, 'EDWARDS_D'):
            a = curve.EDWARDS_A
            d = curve.EDWARDS_D
            
            try:
                # Solve for x²: x² = (y² - 1) / (d * y² - a) mod p
                denominator = (d * y_sq - a) % p
                if denominator == 0:
                    return None
                    
                inv_denominator = pow(denominator, -1, p)
                x_sq = (y_sq - 1) * inv_denominator % p
                
                # For Ed448, p ≡ 3 mod 4, so we can use the simpler method
                # Compute candidate square root: x = x_sq^((p+1)/4) mod p
                # Since p ≡ 3 mod 4, (p+1)/4 is an integer
                x = pow(x_sq, (p + 1) // 4, p)
                
                # Verify the root (x² should equal x_sq mod p)
                if (x * x) % p == x_sq:
                    return x
                    
                # If no solution, try the other root
                x = (p - x) % p
                if (x * x) % p == x_sq:
                    return x
                    
                # If still no solution, try the other possible root from the equation
                # This handles the case where (p+1)/4 is not sufficient
                if p % 8 == 5:
                    x = pow(x_sq, (p + 3) // 8, p)
                    c = pow(2, (p - 1) // 4, p)
                    for _ in range(2):
                        if (x * x) % p == x_sq:
                            return x
                        x = (x * c) % p
                
                return None
                    
            except (ValueError, ZeroDivisionError):
                return None
                
        # Handle Weierstrass curves (if needed in the future)
        # elif hasattr(curve, 'A') and hasattr(curve, 'B'):
        #     # Weierstrass form: y² = x³ + a x + b
        #     # Implementation would go here
        #     pass
            
        # If we get here, the curve type is not supported
        raise NotImplementedError(
            "x-coordinate recovery not implemented for this curve type. "
            "Curve must have EDWARDS_A and EDWARDS_D attributes for Twisted Edwards form."
        )

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
