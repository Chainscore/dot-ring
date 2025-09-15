from __future__ import annotations

from dataclasses import dataclass
from typing import Final, Self, Union, Optional
from dot_ring.curve.point import Point
from dot_ring.curve.short_weierstrass.sw_curve import SWCurve


@dataclass(frozen=True)
class SWAffinePoint(Point[SWCurve]):
    """
    Affine point implementation for Short Weierstrass curves.

    Implements point operations for curves of the form y² = x³ + ax + b.
    """

    def is_on_curve(self) -> bool:
        """
        Check if the point lies on the Short Weierstrass curve.

        Returns:
            bool: True if point is on curve
        """
        x, y = self.x, self.y
        A, B = self.curve.WeierstrassA, self.curve.WeierstrassB
        p = self.curve.PRIME_FIELD
        
        # Check y² = x³ + ax + b
        left_side = (y * y) % p
        right_side = (pow(x, 3, p) + A * x + B) % p
        
        return left_side == right_side

    def __add__(self, other: SWAffinePoint) -> SWAffinePoint:
        """
        Add two points on the Short Weierstrass curve.

        Args:
            other: Point to add

        Returns:
            SWAffinePoint: Result of point addition
        """
        if not isinstance(other, SWAffinePoint):
            raise TypeError("Can only add SWAffinePoint instances")
        
        if self.curve != other.curve:
            raise ValueError("Points must be on the same curve")

        # Handle point at infinity
        if self.is_identity():
            return other
        if other.is_identity():
            return self

        x1, y1 = self.x, self.y
        x2, y2 = other.x, other.y
        p = self.curve.PRIME_FIELD

        # Check if points are inverses
        if x1 == x2 and (y1 + y2) % p == 0:
            return self.identity()

        # Point doubling
        if x1 == x2 and y1 == y2:
            return self._double()

        # Point addition
        # Calculate slope: λ = (y2 - y1) / (x2 - x1)
        numerator = (y2 - y1) % p
        denominator = (x2 - x1) % p
        slope = (numerator * self.curve.mod_inverse(denominator)) % p

        # Calculate result coordinates
        x3 = (slope * slope - x1 - x2) % p
        y3 = (slope * (x1 - x3) - y1) % p

        # The curve is already set in the instance
        return self.__class__(x3, y3)

    def _double(self) -> SWAffinePoint:
        """
        Double a point on the Short Weierstrass curve.

        Returns:
            SWAffinePoint: Result of point doubling
        """
        if self.is_identity():
            return self

        x1, y1 = self.x, self.y
        A = self.curve.WeierstrassA
        p = self.curve.PRIME_FIELD

        # Check if y-coordinate is zero (point has order 2)
        if y1 == 0:
            return self.identity()

        # Calculate slope: λ = (3x₁² + a) / (2y₁)
        numerator = (3 * x1 * x1 + A) % p
        denominator = (2 * y1) % p
        slope = (numerator * self.curve.mod_inverse(denominator)) % p

        # Calculate result coordinates
        x3 = (slope * slope - 2 * x1) % p
        y3 = (slope * (x1 - x3) - y1) % p

        # The curve is already set in the instance
        return self.__class__(x3, y3)

    def __mul__(self, scalar: int) -> SWAffinePoint:
        """
        Scalar multiplication using double-and-add algorithm.

        Args:
            scalar: Scalar to multiply by

        Returns:
            SWAffinePoint: Result of scalar multiplication
        """
        if scalar == 0:
            return self.identity()
        
        if scalar < 0:
            return (-self) * (-scalar)

        # Use binary method (double-and-add)
        result = self.identity()
        addend = self

        while scalar > 0:
            if scalar & 1:
                result = result + addend
            addend = addend._double()
            scalar >>= 1

        return result

    def __neg__(self) -> SWAffinePoint:
        """
        Negate a point (flip y-coordinate).

        Returns:
            SWAffinePoint: Negated point
        """
        if self.is_identity():
            return self
        
        # Create a new instance with negated y-coordinate
        # The curve is already set in the instance
        return self.__class__(self.x, (-self.y) % self.curve.PRIME_FIELD)

    def __sub__(self, other: SWAffinePoint) -> SWAffinePoint:
        """
        Subtract two points.

        Args:
            other: Point to subtract

        Returns:
            SWAffinePoint: Result of point subtraction
        """
        return self + (-other)

    def is_identity(self) -> bool:
        """
        Check if this is the identity element (point at infinity).
        The identity point is represented with None coordinates.

        Returns:
            bool: True if this is the identity element
        """
        return self.x is None and self.y is None

    @classmethod
    def identity(cls) -> SWAffinePoint:
        """
        Get the identity element (point at infinity).

        Returns:
            SWAffinePoint: Identity element
        """
        # This is a simplified representation - in practice, you might want
        # to use projective coordinates or a special flag
        return cls(0, 0, None)  # curve will be set by the specific implementation

    @classmethod
    def _x_recover(cls, y: int) -> int:
        """
        Recover x-coordinate from y-coordinate for point decompression.

        Args:
            y: y-coordinate

        Returns:
            int: Recovered x-coordinate

        Raises:
            ValueError: If x cannot be recovered
        """
        A = cls.curve.WeierstrassA
        B = cls.curve.WeierstrassB
        p = cls.curve.PRIME_FIELD

        # Solve x³ + ax + b - y² = 0 for x
        # This is a cubic equation - we need to find the roots
        rhs = (y * y - B) % p
        
        # For Short Weierstrass curves, we typically solve:
        # x³ + ax = y² - b
        # This is complex, so we'll use a simplified approach
        # In practice, you'd use more sophisticated root-finding algorithms
        
        for x in range(p):
            if (pow(x, 3, p) + A * x + B) % p == (y * y) % p:
                return x
        
        raise ValueError("Cannot recover x-coordinate")

    @classmethod
    def encode_to_curve(cls, message: bytes, salt: bytes = b'') -> SWAffinePoint:
        """
        Encode a message to a curve point using hash-to-curve.

        Args:
            message: Message to encode
            salt: Optional salt

        Returns:
            SWAffinePoint: Encoded point
        """
        # Use the curve's hash-to-field functionality
        combined_input = message + salt
        u_values = cls.curve.hash_to_field(combined_input, 2)
        
        # Map to curve using SSWU
        x, y = cls.curve.map_to_curve_sswu(u_values[0])
        
        return cls(x, y, cls.curve)

    def compress(self) -> bytes:
        """
        Compress point to byte representation.

        Returns:
            bytes: Compressed point representation
        """
        if self.is_identity():
            # Special encoding for point at infinity
            return b'\x00' + b'\x00' * 32

        # Standard SEC1 compression
        prefix = 0x02 if (self.y % 2) == 0 else 0x03
        x_bytes = self.x.to_bytes(32, 'big')
        return bytes([prefix]) + x_bytes

    @classmethod
    def decompress(cls, data: bytes) -> SWAffinePoint:
        """
        Decompress point from byte representation.

        Args:
            data: Compressed point bytes

        Returns:
            SWAffinePoint: Decompressed point

        Raises:
            ValueError: If data is invalid
        """
        if len(data) != 33:
            raise ValueError("Invalid compressed point length")

        prefix = data[0]
        
        if prefix == 0x00:
            return cls.identity()

        if prefix not in (0x02, 0x03):
            raise ValueError("Invalid compression prefix")

        x = int.from_bytes(data[1:], 'big')
        
        # Calculate y² = x³ + ax + b
        A = cls.curve.WeierstrassA
        B = cls.curve.WeierstrassB
        p = cls.curve.PRIME_FIELD
        
        y_squared = (pow(x, 3, p) + A * x + B) % p
        
        if not cls.curve.is_square(y_squared):
            raise ValueError("Point not on curve")
        
        y = cls.curve.mod_sqrt(y_squared)
        
        # Choose correct sign based on prefix
        if (y % 2) != (prefix % 2):
            y = (-y) % p
        
        return cls(x, y, cls.curve)
