from __future__ import annotations

from typing import Self, cast

from dot_ring.curve.e2c import E2C_Variant
from dot_ring.curve.point import CurvePoint
from dot_ring.curve.short_weierstrass.sw_curve import SWCurve


class SWAffinePoint(CurvePoint[SWCurve[int], int]):
    """
    Affine point implementation for Short Weierstrass curves.

    Implements point operations for curves of the form y² = x³ + ax + b.
    """

    def __add__(self, other: SWAffinePoint) -> Self:
        """
        Add two points on the Short Weierstrass curve.

        Args:
            other: Point to add

        Returns:
            Self: Result of point addition
        """
        if not isinstance(other, SWAffinePoint):
            raise TypeError("Can only add SWAffinePoint instances")

        if self.curve != other.curve:
            raise ValueError("Points must be on the same curve")

        # Handle point at infinity
        if self.is_identity():
            return cast(Self, other)
        if other.is_identity():
            return self

        if self.x is None or self.y is None or other.x is None or other.y is None:
            return self.__class__.identity(self.curve)

        x1 = self.x
        y1 = self.y
        x2 = other.x
        y2 = other.y
        p = self.curve.params.field_modulus

        # Check if points are inverses
        if x1 == x2 and (y1 + y2) % p == 0:
            return self.__class__.identity(self.curve)

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
        return self.__class__(x3, y3, self.curve)

    def _double(self) -> Self:
        """
        Double a point on the Short Weierstrass curve.

        Returns:
            Self: Result of point doubling
        """
        if self.is_identity():
            return self

        if self.x is None or self.y is None:
            return self

        x1 = self.x
        y1 = self.y
        A = self.curve.params.a
        p = self.curve.params.field_modulus

        # Check if y-coordinate is zero (point has order 2)
        if y1 == 0:
            return self.__class__.identity(self.curve)

        # Calculate slope: λ = (3x₁² + a) / (2y₁)
        numerator = (3 * x1 * x1 + A) % p
        denominator = (2 * y1) % p
        slope = (numerator * self.curve.mod_inverse(denominator)) % p

        # Calculate result coordinates
        x3 = (slope * slope - 2 * x1) % p
        y3 = (slope * (x1 - x3) - y1) % p

        # The curve is already set in the instance
        return self.__class__(x3, y3, self.curve)

    def __mul__(self, scalar: int) -> Self:
        """
        Scalar multiplication using double-and-add algorithm.

        Args:
            scalar: Scalar to multiply by

        Returns:
            Self: Result of scalar multiplication
        """
        if scalar == 0:
            return self.__class__.identity(self.curve)

        if scalar < 0:
            return (-self) * (-scalar)

        # Use binary method (double-and-add)
        result = self.__class__.identity(self.curve)
        addend = self

        while scalar > 0:
            if scalar & 1:
                result = result + addend
            addend = addend._double()
            scalar >>= 1

        return result

    def __neg__(self) -> Self:
        """
        Negate a point (flip y-coordinate).

        Returns:
            Self: Negated point
        """
        if self.is_identity():
            return self
        if self.x is None or self.y is None:
            return self.__class__.identity(self.curve)

        # Create a new instance with negated y-coordinate
        # The curve is already set in the instance
        return self.__class__(self.x, (-self.y) % self.curve.params.field_modulus, self.curve)

    def __sub__(self, other: SWAffinePoint) -> Self:
        """
        Subtract two points.

        Args:
            other: Point to subtract

        Returns:
            Self: Result of point subtraction
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

        p = self.curve.params.field_modulus
        # Calculate the byte length needed for field elements
        field_byte_len = (p.bit_length() + 7) // 8

        # Convert x-coordinate to bytes
        if self.x is None or self.y is None:
            raise ValueError("Cannot serialize malformed point at infinity")

        x_bytes = self.x.to_bytes(field_byte_len, "big")

        if compressed:
            # Compressed format: prefix (0x02 or 0x03) + x-coordinate
            # Prefix indicates y-coordinate parity
            prefix = b"\x02" if self.y % 2 == 0 else b"\x03"
            return prefix + x_bytes
        else:
            # Uncompressed format: 0x04 + x-coordinate + y-coordinate
            y_bytes = self.y.to_bytes(field_byte_len, "big")
            return b"\x04" + x_bytes + y_bytes

    @classmethod
    def string_to_point(cls, octet_string: str | bytes, curve: SWCurve[int]) -> Self:
        if isinstance(octet_string, str):
            octet_string = bytes.fromhex(octet_string)

        if len(octet_string) == 0:
            raise ValueError("Empty octet string")

        prefix = octet_string[0]

        # Handle point at infinity
        if prefix == 0x00:
            if len(octet_string) != 1:
                raise ValueError("Point at infinity must be single byte 0x00")
            return cls.identity(curve)

        p = curve.params.field_modulus
        A = curve.params.a
        B = curve.params.b
        field_byte_len = (p.bit_length() + 7) // 8

        # Handle compressed format (0x02 or 0x03)
        if prefix in (0x02, 0x03):
            expected_len = 1 + field_byte_len
            if len(octet_string) != expected_len:
                raise ValueError(f"Invalid compressed point length: expected {expected_len}, got {len(octet_string)}")

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
                raise ValueError("Invalid point encoding")

            # Choose correct square root based on parity indicated by prefix
            # prefix 0x02: y should be even
            # prefix 0x03: y should be odd
            if (y % 2 == 0 and prefix == 0x03) or (y % 2 == 1 and prefix == 0x02):
                y = p - y  # Use the other square root

            point = cls(x, y, curve)

            # Verify point is on curve
            if not point.is_on_curve():
                raise ValueError(f"Decompressed point ({x}, {y}) is not on curve")

            return point

        # Handle uncompressed format (0x04)
        elif prefix == 0x04:
            expected_len = 1 + 2 * field_byte_len
            if len(octet_string) != expected_len:
                raise ValueError(f"Invalid uncompressed point length: expected {expected_len}, got {len(octet_string)}")

            # Extract x and y coordinates
            x_bytes = octet_string[1 : 1 + field_byte_len]
            y_bytes = octet_string[1 + field_byte_len :]

            x = int.from_bytes(x_bytes, "big")
            y = int.from_bytes(y_bytes, "big")

            # Validate coordinates are in field
            if x >= p:
                raise ValueError(f"x-coordinate {x} is not in field Fp (p={p})")
            if y >= p:
                raise ValueError(f"y-coordinate {y} is not in field Fp (p={p})")

            point = cls(x, y, curve)

            # Verify point is on curve
            if not point.is_on_curve():
                raise ValueError(f"Point ({x}, {y}) is not on curve")

            return point

        # Handle hybrid format (0x06 or 0x07) - optional, not commonly used
        elif prefix in (0x06, 0x07):
            # Hybrid format: prefix + x + y, where prefix encodes y parity redundantly
            expected_len = 1 + 2 * field_byte_len
            if len(octet_string) != expected_len:
                raise ValueError(f"Invalid hybrid point length: expected {expected_len}, got {len(octet_string)}")

            x_bytes = octet_string[1 : 1 + field_byte_len]
            y_bytes = octet_string[1 + field_byte_len :]

            x = int.from_bytes(x_bytes, "big")
            y = int.from_bytes(y_bytes, "big")

            # Validate coordinates are in field
            if x >= p or y >= p:
                raise ValueError("Coordinates not in field")

            # Verify y parity matches prefix
            if (y % 2 == 0 and prefix == 0x07) or (y % 2 == 1 and prefix == 0x06):
                raise ValueError("Hybrid format: y parity doesn't match prefix")

            point = cls(x, y, curve)

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
        if self.x is None or self.y is None:
            return False

        return 0 <= self.x < self.curve.params.field_modulus and 0 <= self.y < self.curve.params.field_modulus

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
        if self.x is None or self.y is None:
            return False
        return self.curve.is_on_curve((self.x, self.y))

    def clear_cofactor(self) -> Self:
        return cast(Self, self * self.curve.params.cofactor)

    def is_identity(self) -> bool:
        """
        Check if this is the identity element (point at infinity).
        The identity point is represented with None coordinates.

        Returns:
            bool: True if this is the identity element
        """
        return self.x is None and self.y is None

    @classmethod
    def identity(cls, curve: SWCurve[int]) -> Self:
        """
        Get the identity element (point at infinity).

        Returns:
            Self: Identity element
        """
        # Return a point at infinity (None, None)
        return cls(None, None, curve)

    @staticmethod
    def tonelli_shanks(n: int, p: int) -> int | None:
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
            for i in range(1, m):  # noqa: B007
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
    def _x_recover(cls, y: int, curve: SWCurve[int]) -> tuple[int, int]:
        p = curve.params.field_modulus
        B = curve.params.b

        # Compute right-hand side of the curve equation
        rhs = (pow(y, 2, p) - B) % p

        # Solve for x: x³ + A x = rhs mod p
        # This requires solving cubic — but we do it by Tonelli–Shanks
        x = cls.tonelli_shanks(rhs, p)
        if x is None:
            raise ValueError("No x found for given y")

        return x, (-x) % p

    @classmethod
    def map_to_curve_simple_swu(cls, u: int, curve: SWCurve[int]) -> Self:
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

        hash_to_curve = curve.params.hash_to_curve
        isogeny = hash_to_curve.isogeny
        Z = hash_to_curve.z
        A = curve.params.a
        B = curve.params.b
        if isogeny is not None:
            A = isogeny.map_curve.a
            B = isogeny.map_curve.b
        p = curve.params.field_modulus

        # 1. tv1 = inv0(Z^2 * u^4 + Z * u^2)
        u_sq = (u * u) % p
        tv1 = (Z * Z * ((u_sq * u_sq) % p) + Z * u_sq) % p

        # Handle special case when tv1 is 0
        if tv1 == 0:
            # 3. If tv1 == 0, set x1 = B / (Z * A)
            x1 = (B * curve.inv((Z * A) % p)) % p
        else:
            # 2. x1 = (-B / A) * (1 + tv1)
            tv1 = curve.inv(tv1)
            x1 = (-B * curve.inv(A)) % p
            x1 = (x1 * (1 + tv1)) % p

        # 4. gx1 = x1^3 + A * x1 + B
        gx1 = (pow(x1, 3, p) + (A * x1) % p + B) % p

        # 5. x2 = Z * u^2 * x1
        x2 = (Z * u_sq % p) * x1 % p

        # 6. gx2 = x2^3 + A * x2 + B
        gx2 = (pow(x2, 3, p) + (A * x2) % p + B) % p

        # 7-8. Find a valid x and y
        x, y = x1, None
        if curve.is_square(gx1):
            y = curve.mod_sqrt(gx1)
        else:
            x = x2
            y = curve.mod_sqrt(gx2)

        # 9. Fix sign of y
        if curve.sgn0(u) != curve.sgn0(y):
            y = (-y) % p

        if isogeny is not None:
            map_curve = isogeny.map_curve
            # Check if point lies on E'
            if (y * y - (x**3 + map_curve.a * x + map_curve.b)) % p != 0:
                raise ValueError("Point is not on the hash-to-curve map curve")
            return cls.apply_isogeny(x, y, curve)

        return cls(x=x, y=y, curve=curve)

    @classmethod
    def encode_to_curve(
        cls,
        alpha_string: bytes | str,
        salt: bytes | str = b"",
        curve: SWCurve[int] | None = None,
    ) -> Self:
        if curve is None:
            raise ValueError("curve is required")
        if not isinstance(alpha_string, bytes):
            alpha_string = bytes.fromhex(alpha_string)

        if not isinstance(salt, bytes):
            salt = bytes.fromhex(salt)

        if curve.e2c_variant == E2C_Variant.TAI:
            from dot_ring.vrf.transcript import hash_to_curve_tai

            return cast(Self, hash_to_curve_tai(cls, salt + alpha_string, curve))

        if curve.e2c_variant in (E2C_Variant.SSWU, E2C_Variant.SSWU_NU):
            if curve.e2c_variant.value.endswith("_NU_"):
                return cls._encode_sswu_nu(alpha_string, curve, salt)
            return cls._encode_sswu_ro(alpha_string, curve, salt)

        raise ValueError(f"Unexpected E2C Variant: {curve.e2c_variant}")

    @classmethod
    def _encode_sswu_ro(
        cls,
        alpha_string: bytes,
        curve: SWCurve[int],
        salt: bytes = b"",
    ) -> Self:
        """Encode with the random-oracle simplified-SWU hash-to-curve variant."""
        string_to_hash = salt + alpha_string
        u0, u1 = curve.hash_to_field(string_to_hash, 2)
        q0 = cls.map_to_curve_simple_swu(u0, curve)
        q1 = cls.map_to_curve_simple_swu(u1, curve)
        R = q0 + q1
        return cast(Self, R.clear_cofactor())

    @classmethod
    def _encode_sswu_nu(
        cls,
        alpha_string: bytes,
        curve: SWCurve[int],
        salt: bytes = b"",
    ) -> Self:
        """Encode with the nonuniform simplified-SWU hash-to-curve variant."""
        string_to_hash = salt + alpha_string
        (u0,) = curve.hash_to_field(string_to_hash, 1)
        return cast(Self, cls.map_to_curve_simple_swu(u0, curve).clear_cofactor())

    @classmethod
    def apply_isogeny(cls, x_p: int, y_p: int, curve: SWCurve[int]) -> Self:
        """
        Apply the rational isogeny map to a point (x', y') on the isogenous curve E'.
        """
        p = curve.params.field_modulus
        isogeny = curve.params.hash_to_curve.isogeny
        if isogeny is None:
            raise ValueError("Missing isogeny")

        def evaluate(coefficients: tuple[int, ...], x: int) -> int:
            value = 0
            for coefficient in coefficients:
                value = (value * x + coefficient) % p
            return value

        x_num = evaluate(isogeny.x_numerator, x_p)
        x_den = evaluate(isogeny.x_denominator, x_p)
        y_num = evaluate(isogeny.y_numerator, x_p)
        y_den = evaluate(isogeny.y_denominator, x_p)

        x_den_inv = pow(x_den, -1, p)
        y_den_inv = pow(y_den, -1, p)

        x_mapped = (x_num * x_den_inv) % p
        y_mapped = (y_p * y_num * y_den_inv) % p

        return cls(x_mapped, y_mapped, curve)
