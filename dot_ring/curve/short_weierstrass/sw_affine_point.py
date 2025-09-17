from __future__ import annotations

from dataclasses import dataclass
from typing import Final, Self, Union, Optional, Any
from dot_ring.curve.point import Point
from dot_ring.curve.short_weierstrass.sw_curve import SWCurve
from dot_ring.curve.e2c import E2C_Variant


@dataclass(frozen=True)
class SWAffinePoint(Point[SWCurve]):
    """
    Affine point implementation for Short Weierstrass curves.

    Implements point operations for curves of the form y² = x³ + ax + b.
    """

    def is_on_curve(self) -> bool:
        """
        Check if the point lies on the Short Weierstrass curve.
        
        The point at infinity (None, None) is considered to be on the curve.

        Returns:
            bool: True if point is on curve
        """
        # Point at infinity is always on the curve
        if self.x is None and self.y is None:
            return True
            
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

    def clear_cofactor(self)-> SWAffinePoint:
        return self*self.curve.COFACTOR


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
        # Return a point at infinity (None, None)
        # The curve will be set by the child class's __init__
        return cls(None, None)

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

    @classmethod
    def map_to_curve_simple_swu(cls, u: int)->SWAffinePoint:
        """
        Implements simplified SWU mapping
        """
        # 1.tv1 = inv0(Z ^ 2 * u ^ 4 + Z * u ^ 2)
        # 2.x1 = (-B / A) * (1 + tv1)
        # 3.Iftv1 == 0, set x1 = B / (Z * A)
        # 4.gx1 = x1 ^ 3 + A * x1 + B
        # 5.x2 = Z * u ^ 2 * x1
        # 6.gx2 = x2 ^ 3 + A * x2 + B
        # 7.Ifis_square(gx1), setx = x1 and y = sqrt(gx1)
        # 8.Else set x = x2 and y = sqrt(gx2)
        # 9.If sgn0(u) != sgn0(y), set y = -y
        # 10.return (x, y)
        Z = cls.curve.Z
        A=cls.curve.WeierstrassA
        B=cls.curve.WeierstrassB

        Zp2 = Z * Z
        up4 = u * u * u * u
        up2 = u * u
        tv1 = (Zp2 * up4 + Z * up2)
        tv1 = cls.curve.inv(tv1)
        x1 = ((-B * cls.curve.inv(A)) * (1 + tv1)) % cls.curve.PRIME_FIELD
        if tv1 == 0:
            x1 = (B / (Z * A)) % cls.curve.PRIME_FIELD
        gx1 = (x1 * x1 * x1 + A * x1 + B) % cls.curve.PRIME_FIELD
        x2 = (Z * u * u * x1) % cls.curve.PRIME_FIELD
        gx2 = (x2 * x2 * x2 + A * x2 + B) % cls.curve.PRIME_FIELD
        if cls.curve.is_square(gx1):
            x = x1
            y = cls.curve.mod_sqrt(gx1)
        else:
            x = x2
            y = cls.curve.mod_sqrt(gx2)
        if cls.curve.sgn0(u) != cls.curve.sgn0(y):
            y = (-y) % cls.curve.PRIME_FIELD
        # Create point using the proper constructor
        return cls(x=x, y=y)

    @classmethod
    def encode_to_curve(cls, alpha_string: bytes | str, salt: bytes | str = b"", General_Check:bool=False) -> Self|Any:


        if not isinstance(alpha_string, bytes):
            alpha_string = bytes.fromhex(alpha_string)

        if not isinstance(salt, bytes):
            salt = bytes.fromhex(salt)

        if cls.curve.E2C == E2C_Variant.SSWU:
            return cls.sswu_hash2_curve(alpha_string, salt, General_Check)
        else:
            raise ValueError("Unexpected E2C Variant")

    @classmethod
    def sswu_hash2_curve(cls, alpha_string: bytes, salt: bytes = b"", General_Check:bool=False) ->SWAffinePoint|Any:
        """
        Encode a string to a curve point using Elligator 2.

        Args:
            alpha_string: String to encode
            salt: Optional salt for the encoding
            General_Check:Just for printing all test suites

        Returns:
            TEAffinePoint: Resulting curve point
        """
        string_to_hash = salt + alpha_string
        u = cls.curve.hash_to_field(string_to_hash, 2) #for RO

        q0 = cls.map_to_curve_simple_swu(u[0])  # sswu
        q1 = cls.map_to_curve_simple_swu(u[1])  # sswu
        R = q0 + q1
        if General_Check:
            P=R.clear_cofactor()
            return {
                "u": u,
                "Q0": [q0.x, q0.y],
                "Q1": [q1.x, q1.y],
                "P": [P.x, P.y]
            }
        return R.clear_cofactor()