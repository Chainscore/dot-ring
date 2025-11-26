from __future__ import annotations

from dataclasses import dataclass
from typing import  Self, Union, Optional, Any, TypeVar

from dot_ring.curve.point import CurvePoint
from dot_ring.curve.short_weierstrass.sw_curve import SWCurve
from dot_ring.curve.e2c import E2C_Variant
from ..field_element import FieldElement

T = TypeVar('T', bound='SWAffinePoint')

class SWAffinePoint(CurvePoint):
    """
    Affine point implementation for Short Weierstrass curves.

    Implements point operations for curves of the form y² = x³ + ax + b.
    """

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

    def point_to_string(self, compressed: bool = True) -> bytes:
        """
        Convert elliptic curve point (x, y) to compressed octet string
        according to SEC1 standard for short Weierstrass curves.

        Returns:
            bytes: The compressed point representation
        """
        # Handle point at infinity
        if self.x is None and self.y is None:
            return b"\x00"

        p = self.curve.PRIME_FIELD
        # Calculate the byte length needed for field elements
        field_byte_len = (p.bit_length() + 7) // 8

        # Convert x-coordinate to bytes
        x_bytes = int(self.x).to_bytes(field_byte_len, "big")

        if compressed:
            # Compressed format: prefix (0x02 or 0x03) + x-coordinate
            # Prefix indicates y-coordinate parity
            prefix = b"\x02" if self.y % 2 == 0 else b"\x03"
            return prefix + x_bytes
        else:
            # Uncompressed format: 0x04 + x-coordinate + y-coordinate
            y_bytes = int(self.y).to_bytes(field_byte_len, "big")
            return b"\x04" + x_bytes + y_bytes


    @classmethod
    def string_to_point(cls, octet_string: Union[str, bytes]) -> 'Point[C]'|str:
        if isinstance(octet_string, str):
            octet_string = bytes.fromhex(octet_string)

        if len(octet_string) == 0:
            raise ValueError("Empty octet string")

        prefix = octet_string[0]

        # Handle point at infinity
        if prefix == 0x00:
            if len(octet_string) != 1:
                raise ValueError("Point at infinity must be single byte 0x00")
            return cls.identity()

        p = cls.curve.PRIME_FIELD
        A = cls.curve.WeierstrassA
        B = cls.curve.WeierstrassB
        field_byte_len = (p.bit_length() + 7) // 8

        # Handle compressed format (0x02 or 0x03)
        if prefix in (0x02, 0x03):
            expected_len = 1 + field_byte_len
            if len(octet_string) != expected_len:
                raise ValueError(
                    f"Invalid compressed point length: expected {expected_len}, got {len(octet_string)}"
                )

            # Extract x-coordinate
            x_bytes = octet_string[1:]
            x = int.from_bytes(x_bytes, "big")

            # Validate x is in field
            if x >= p:
                raise ValueError(f"x-coordinate {x} is not in field Fp (p={p})")

            # Compute y² = x³ + Ax + B mod p
            y_squared = (pow(x, 3, p) + A * x + B) % p

            # Compute square root using Tonelli-Shanks
            y = cls.tonelli_shanks(y_squared, p)
            if y is None:
                # raise ValueError(
                #     f"Point decompression failed: no square root exists for y² ≡ {y_squared} (mod {p})"
                # )
                return "INVALID"

            # Choose correct square root based on parity indicated by prefix
            # prefix 0x02: y should be even
            # prefix 0x03: y should be odd
            if (y % 2 == 0 and prefix == 0x03) or (y % 2 == 1 and prefix == 0x02):
                y = p - y  # Use the other square root

            point = cls(x, y)

            # Verify point is on curve
            if not point.is_on_curve():
                raise ValueError(f"Decompressed point ({x}, {y}) is not on curve")

            return point

        # Handle uncompressed format (0x04)
        elif prefix == 0x04:
            expected_len = 1 + 2 * field_byte_len
            if len(octet_string) != expected_len:
                raise ValueError(
                    f"Invalid uncompressed point length: expected {expected_len}, got {len(octet_string)}"
                )

            # Extract x and y coordinates
            x_bytes = octet_string[1:1 + field_byte_len]
            y_bytes = octet_string[1 + field_byte_len:]

            x = int.from_bytes(x_bytes, "big")
            y = int.from_bytes(y_bytes, "big")

            # Validate coordinates are in field
            if x >= p:
                raise ValueError(f"x-coordinate {x} is not in field Fp (p={p})")
            if y >= p:
                raise ValueError(f"y-coordinate {y} is not in field Fp (p={p})")

            point = cls(x, y)

            # Verify point is on curve
            if not point.is_on_curve():
                raise ValueError(f"Point ({x}, {y}) is not on curve")

            return point

        # Handle hybrid format (0x06 or 0x07) - optional, not commonly used
        elif prefix in (0x06, 0x07):
            # Hybrid format: prefix + x + y, where prefix encodes y parity redundantly
            expected_len = 1 + 2 * field_byte_len
            if len(octet_string) != expected_len:
                raise ValueError(
                    f"Invalid hybrid point length: expected {expected_len}, got {len(octet_string)}"
                )

            x_bytes = octet_string[1:1 + field_byte_len]
            y_bytes = octet_string[1 + field_byte_len:]

            x = int.from_bytes(x_bytes, "big")
            y = int.from_bytes(y_bytes, "big")

            # Validate coordinates are in field
            if x >= p or y >= p:
                raise ValueError("Coordinates not in field")

            # Verify y parity matches prefix
            if (y % 2 == 0 and prefix == 0x07) or (y % 2 == 1 and prefix == 0x06):
                raise ValueError("Hybrid format: y parity doesn't match prefix")

            point = cls(x, y)

            if not point.is_on_curve():
                raise ValueError(f"Point ({x}, {y}) is not on curve")

            return point

        else:
            raise ValueError(
                f"Invalid point encoding prefix: 0x{prefix:02x}. "
                f"Expected 0x00 (infinity), 0x02/0x03 (compressed), 0x04 (uncompressed), or 0x06/0x07 (hybrid)"
            )


    def _validate_coordinates(self) -> bool:
        """
        Validate point coordinates are within field bounds.

        Returns:
            bool: True if coordinates are valid
        """
        # Handle point at infinity
        if self.x is None and self.y is None:
            return True

        # Handle FieldElement points (for Fp2)
        if hasattr(self.x, 're') and hasattr(self.y, 're'):
            # For FieldElement, check that the prime field matches
            return (self.x.p == self.curve.PRIME_FIELD and
                    self.y.p == self.curve.PRIME_FIELD and
                    0 <= self.x.re < self.curve.PRIME_FIELD and
                    0 <= self.x.im < self.curve.PRIME_FIELD and
                    0 <= self.y.re < self.curve.PRIME_FIELD and
                    0 <= self.y.im < self.curve.PRIME_FIELD)

        # Handle Fp2 points (tuples of two integers)
        if isinstance(self.x, (tuple, list)) and isinstance(self.y, (tuple, list)):
            if len(self.x) != 2 or len(self.y) != 2:
                return False
            return all(isinstance(coord, int) and 0 <= coord < self.curve.PRIME_FIELD
                       for coord in (*self.x, *self.y))

        # Handle Fp points (integers)
        if isinstance(self.x, int) and isinstance(self.y, int):
            return (0 <= self.x < self.curve.PRIME_FIELD and
                    0 <= self.y < self.curve.PRIME_FIELD)

        return False

    def is_on_curve(self) -> bool:
        """
        Check if the point lies on the curve.

        The curve equation is y² = x³ + ax + b

        Returns:
            bool: True if point is on the curve
        """
        # Point at infinity is on the curve
        if self.x is None and self.y is None:
            return True
        # For FieldElement points (Fp2)
        if hasattr(self.x, 're') and hasattr(self.y, 're'):
            # y²
            y2 = self.y * self.y

            # x³ + a*x + b
            x3 = self.x * self.x * self.x
            a = FieldElement(
                self.curve.WeierstrassA[0],
                self.curve.WeierstrassA[1],
                self.curve.PRIME_FIELD
            )
            b = FieldElement(
                self.curve.WeierstrassB[0],
                self.curve.WeierstrassB[1],
                self.curve.PRIME_FIELD
            )
            rhs = x3 + (a * self.x) + b

            return y2 == rhs

        # For Fp2 points (tuples of two integers)
        if isinstance(self.x, (tuple, list)) and isinstance(self.y, (tuple, list)):
            # TODO: Implement proper Fp2 arithmetic for curve equation check
            # This is a simplified check that only validates the point is in the field
            return self._validate_coordinates()

        # For Fp points, use standard arithmetic
        try:
            left = pow(self.y, 2, self.curve.PRIME_FIELD)
            right = (pow(self.x, 3, self.curve.PRIME_FIELD) +
                     self.curve.WeierstrassA * self.x +
                     self.curve.WeierstrassB) % self.curve.PRIME_FIELD
            return left == right
        except (TypeError, AttributeError):
            return False

    def clear_cofactor(self) -> SWAffinePoint:
        return self * self.curve.COFACTOR

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

    @staticmethod
    def tonelli_shanks(n: int, p: int) -> Optional[int]:
        if pow(n, (p - 1) // 2, p) != 1:
            return None  # No square root exists

            # Special case for p ≡ 3 (mod 4)
        if p % 4 == 3:
            return pow(n, (p + 1) // 4, p)

            # General case: Tonelli-Shanks algorithm
            # Factor p - 1 = q * 2^s where q is odd
        q, s = p - 1, 0
        while q % 2 == 0:
            q //= 2
            s += 1

        # Find a quadratic non-residue z
        z = 2
        while pow(z, (p - 1) // 2, p) != p - 1:
            z += 1

        # Initialize variables
        m = s
        c = pow(z, q, p)
        t = pow(n, q, p)
        r = pow(n, (q + 1) // 2, p)

        # Iteratively compute the square root
        while t != 1:
            # Find the least i such that t^(2^i) = 1
            t2i = t
            for i in range(1, m):
                t2i = pow(t2i, 2, p)
                if t2i == 1:
                    break

            # Update variables
            b = pow(c, 1 << (m - i - 1), p)
            m = i
            c = pow(b, 2, p)
            t = (t * c) % p
            r = (r * b) % p

        return r

    @classmethod
    def _x_recover(cls, y: int) -> int:
        p = cls.curve.PRIME_FIELD
        A = cls.curve.WeierstrassA
        B = cls.curve.WeierstrassB

        # Compute right-hand side of the curve equation
        rhs = (pow(y, 2, p) - B) % p

        # Solve for x: x³ + A x = rhs mod p
        # This requires solving cubic — but we do it by Tonelli–Shanks
        x = cls.tonelli_shanks(rhs, p)
        if x is None:
            raise ValueError("No x found for given y")

        return x


    @classmethod
    def map_to_curve_simple_swu(cls, u: int) -> SWAffinePoint | Any:
        """Implements simplified SWU mapping"""
        # 1.  tv1 = inv0(Z^2 * u^4 + Z * u^2)
        # 2.   x1 = (-B / A) * (1 + tv1)
        # 3.  If tv1 == 0, set x1 = B / (Z * A)
        # 4. gx1 = x1^3 + A * x1 + B
        # 5.  x2 = Z * u^2 * x1
        # 6. gx2 = x2^3 + A * x2 + B
        # 7.  If is_square(gx1), set x = x1 and y = sqrt(gx1)
        # 8.  Else set x = x2 and y = sqrt(gx2)
        # 9.  If sgn0(u) != sgn0(y), set y = -y
        # 10. return (x, y)

        Z = cls.curve.Z
        A = cls.curve.WeierstrassA
        B = cls.curve.WeierstrassB
        p = cls.curve.PRIME_FIELD

        if cls.curve.Requires_Isogeny:  # E' vals, used only for secp256k1 as its A=0
            A = 0x3f8731abdd661adca08a5558f0f5d272e953d363cb6f0e5d405447c01a444533
            B = 1771

        # 1. tv1 = inv0(Z^2 * u^4 + Z * u^2)
        u_sq = (u * u) % p
        tv1 = (Z * Z * ((u_sq * u_sq) % p) + Z * u_sq) % p

        # Handle special case when tv1 is 0
        if tv1 == 0:
            # 3. If tv1 == 0, set x1 = B / (Z * A)
            x1 = (B * cls.curve.inv((Z * A) % p)) % p
        else:
            # 2. x1 = (-B / A) * (1 + tv1)
            tv1 = cls.curve.inv(tv1)
            x1 = (-B * cls.curve.inv(A)) % p
            x1 = (x1 * (1 + tv1)) % p

        # 4. gx1 = x1^3 + A * x1 + B
        gx1 = (pow(x1, 3, p) + (A * x1) % p + B) % p

        # 5. x2 = Z * u^2 * x1
        x2 = (Z * u_sq % p) * x1 % p

        # 6. gx2 = x2^3 + A * x2 + B
        gx2 = (pow(x2, 3, p) + (A * x2) % p + B) % p

        # 7-8. Find a valid x and y
        x, y = x1, None
        if cls.curve.is_square(gx1):
            y = cls.curve.mod_sqrt(gx1)
        else:
            x = x2
            y = cls.curve.mod_sqrt(gx2)

        # 9. Fix sign of y
        if cls.curve.sgn0(u) != cls.curve.sgn0(y):
            y = (-y) % p

        if cls.curve.Requires_Isogeny:

            A_prime = 0x3f8731abdd661adca08a5558f0f5d272e953d363cb6f0e5d405447c01a444533
            B_prime = 1771

            # Check if point lies on E'
            if (y * y - (x ** 3 + A_prime * x + B_prime)) % p != 0:
                raise ValueError("Point is not on E'")
            return cls.apply_isogeny(x, y)

        return cls(x=x, y=y)

    @classmethod
    def encode_to_curve(cls, alpha_string: bytes | str, salt: bytes | str = b"",
                        General_Check: bool = False) -> Self | Any:

        if not isinstance(alpha_string, bytes):
            alpha_string = bytes.fromhex(alpha_string)

        if not isinstance(salt, bytes):
            salt = bytes.fromhex(salt)

        if cls.curve.E2C in [E2C_Variant.SSWU,E2C_Variant.SSWU_NU]:
            if cls.curve.E2C.value.endswith("_NU_"):
                return cls.sswu_hash2_curve_nu(alpha_string, salt, General_Check)
            return cls.sswu_hash2_curve_ro(alpha_string, salt, General_Check)
        elif cls.curve.E2C == E2C_Variant.TAI:
            return cls.encode_to_curve_tai(alpha_string, salt)
        else:
            raise ValueError(f"Unexpected E2C Variant: {cls.curve.E2C}")


    @classmethod
    def sswu_hash2_curve_ro(cls, alpha_string: bytes, salt: bytes = b"",
                            General_Check: bool = False) -> SWAffinePoint | Any:
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
        u = cls.curve.hash_to_field(string_to_hash, 2)  # for RO
        q0 = cls.map_to_curve_simple_swu(u[0])  # sswu
        q1 = cls.map_to_curve_simple_swu(u[1])  # sswu
        R = q0 + q1

        if General_Check:
            P = R.clear_cofactor()
            return {
                "u": u,
                "Q0": [q0.x, q0.y],
                "Q1": [q1.x, q1.y],
                "P": [P.x, P.y]
            }
        return R.clear_cofactor()

    @classmethod
    def sswu_hash2_curve_nu(cls, alpha_string: bytes, salt: bytes = b"",
                            General_Check: bool = False) -> SWAffinePoint | Any:
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
        u = cls.curve.hash_to_field(string_to_hash, 1)  # for nu
        R = cls.map_to_curve_simple_swu(u[0])  # sswu
        if General_Check:
            P = R.clear_cofactor()
            return {
                "u": u,
                "Q0": [R.x, R.y],
                "P": [P.x, P.y]
            }
        return R.clear_cofactor()

    @classmethod
    def apply_isogeny(cls, x_p: int, y_p: int) -> Self:
        """
        Apply the rational isogeny map to a point (x', y') on the isogenous curve E'.
        Explicit polynomial formulas for secp256k1.
        """
        p = cls.curve.PRIME_FIELD
        coeffs = cls.curve.Isogeny_Coeffs
        x_num = (
                        coeffs["x_num"][0] * pow(x_p, 3, p) +
                        coeffs["x_num"][1] * pow(x_p, 2, p) +
                        coeffs["x_num"][2] * x_p +
                        coeffs["x_num"][3]
                ) % p

        x_den = (
                        pow(x_p, 2, p) +
                        coeffs["x_den"][1] * x_p +
                        coeffs["x_den"][2]
                ) % p
        y_num = (
                        coeffs["y_num"][0] * pow(x_p, 3, p) +
                        coeffs["y_num"][1] * pow(x_p, 2, p) +
                        coeffs["y_num"][2] * x_p +
                        coeffs["y_num"][3]
                ) % p

        y_den = (
                        pow(x_p, 3, p) +
                        coeffs["y_den"][1] * pow(x_p, 2, p) +
                        coeffs["y_den"][2] * x_p +
                        coeffs["y_den"][3]
                ) % p

        x_den_inv = pow(x_den, -1, p)
        y_den_inv = pow(y_den, -1, p)

        x_mapped = (x_num * x_den_inv) % p
        y_mapped = (y_p * y_num * y_den_inv) % p

        return cls(x_mapped, y_mapped)