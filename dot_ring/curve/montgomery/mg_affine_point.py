from __future__ import annotations

from typing import TypeVar, cast

from dot_ring.curve.e2c import E2C_Variant

from ..point import CurvePoint
from .mg_curve import MGCurve

C = TypeVar("C", bound=MGCurve)


class MGAffinePoint(CurvePoint[C, int]):
    """
    Affine point on a Montgomery curve.

    Notes:
      - Identity is represented by x=None, y=None.
      - __class__ tries constructor signatures (x,y,curve) and (x,y) and falls
        back to creating an instance directly if necessary.
      - Addition/doubling use canonical Montgomery affine formulas:
          lambda = (y2 - y1)/(x2 - x1)
          x3 = B*lambda^2 - A - x1 - x2
          y3 = lambda*(x1 - x3) - y1
        Doubling:
          lambda = (3*x1^2 + 2*A*x1 + 1) / (2*B*y1)
    """

    def is_on_curve(self) -> bool:
        """Check if point is on the curve."""
        # identity is considered on-curve by convention
        if self.is_identity():
            return True
        if self.x is None or self.y is None:
            return False
        return self.curve.is_on_curve((cast(int, self.x), cast(int, self.y)))

    def __add__(self, other: MGAffinePoint[C]) -> MGAffinePoint[C]:
        """
        Affine point addition on Montgomery curve.

        Uses canonical affine formulas:
          - slope lambda = (y2 - y1) / (x2 - x1)
          - x3 = B*lambda^2 - A - x1 - x2
          - y3 = lambda*(x1 - x3) - y1

        Doubling uses:
          lambda = (3*x1^2 + 2*A*x1 + 1) / (2*B*y1)
        """
        if not isinstance(other, MGAffinePoint):
            return NotImplemented
        if self.curve != other.curve:
            raise ValueError("Points must be on the same curve")

        # identity cases
        if self.is_identity():
            return other
        if other.is_identity():
            return self

        p = self.curve.params.field_modulus
        A = self.curve.params.a
        B = self.curve.params.b

        # ensure coords are ints mod p
        if self.x is None or self.y is None or other.x is None or other.y is None:
            # Should be handled by is_identity checks above, but for mypy:
            return self.__class__(None, None)

        x1, y1 = self.x % p, self.y % p
        x2, y2 = other.x % p, other.y % p

        # Doubling
        if x1 == x2 and y1 == y2:
            # if y == 0 then slope denominator = 0 => result is identity
            if y1 % p == 0:
                return self.__class__(None, None)
            numerator = (3 * x1 * x1 + 2 * A * x1 + 1) % p
            denominator = (2 * B * y1) % p
            # Check if denominator is zero before computing inverse
            if denominator == 0:
                return self.__class__(None, None)
            lam = (numerator * pow(denominator, -1, p)) % p
            x3 = (B * (lam * lam % p) - A - 2 * x1) % p
            y3 = (lam * (x1 - x3) - y1) % p
            return self.__class__(x3, y3)

        # Addition for distinct points
        if x1 == x2:
            # vertical line -> identity (x1 == x2 but y1 != y2)
            return self.__class__(None, None)

        numerator = (y2 - y1) % p
        denominator = (x2 - x1) % p
        # Check if denominator is zero (shouldn't happen since x1 != x2)
        if denominator == 0:
            raise ValueError("Unexpected zero denominator in point addition")
        lam = (numerator * pow(denominator, -1, p)) % p
        # Corrected formula for x3 in point addition
        x3 = (B * lam * lam - A - x1 - x2) % p
        # Corrected formula for y3
        y3 = (lam * (x1 - x3) - y1) % p
        return self.__class__(x3, y3)

    def __neg__(self) -> MGAffinePoint[C]:
        """Negate a point (x, y) -> (x, -y)."""
        if self.is_identity() or self.x is None or self.y is None:
            return self.__class__(None, None)
        return self.__class__(
            self.x % self.curve.params.field_modulus,
            (-self.y) % self.curve.params.field_modulus,
        )

    def __sub__(self, other: MGAffinePoint[C]) -> MGAffinePoint[C]:
        """Subtract points by adding the negation."""
        return self + (-other)

    def _sqrt_mod_p(self, n: int) -> int | None:
        """
        Compute sqrt(n) mod p. Use p % 8 == 5 optimization if applicable, else
        Tonelli-Shanks.
        Returns one square root or None if none exists.
        """
        p = self.curve.params.field_modulus
        n = n % p  # Ensure n is in range [0, p)

        if n == 0:
            return 0

        # Legendre symbol check
        if pow(n, (p - 1) // 2, p) != 1:
            return None

        # Special case for p ≡ 3 (mod 4) - simpler than p ≡ 5 (mod 8)
        if p % 4 == 3:
            return pow(n, (p + 1) // 4, p)

        if p % 8 == 5:
            # sqrt = n^{(p+3)/8} or times sqrt(-1)
            r = pow(n, (p + 3) // 8, p)
            if (r * r) % p == n % p:
                return r
            # Try r * sqrt(-1) where sqrt(-1) = 2^((p-1)/4)
            sqrt_minus_one = pow(2, (p - 1) // 4, p)
            r = (r * sqrt_minus_one) % p
            if (r * r) % p == n % p:
                return r
            return None

        # Tonelli-Shanks general method
        # Factor p-1 = Q * 2^S with Q odd
        Q = p - 1
        S = 0
        while Q % 2 == 0:
            Q //= 2
            S += 1

        # find a quadratic non-residue z
        z = 2
        while pow(z, (p - 1) // 2, p) != p - 1:
            z += 1

        M = S
        c = pow(z, Q, p)
        t = pow(n, Q, p)
        R = pow(n, (Q + 1) // 2, p)

        while t != 1:
            # find least i (0 < i < M) such that t^{2^i} == 1
            i = 1
            t2i = (t * t) % p
            while i < M and t2i != 1:
                t2i = (t2i * t2i) % p
                i += 1
            if i == M:
                return None
            b = pow(c, 1 << (M - i - 1), p)
            M = i
            c = (b * b) % p
            R = (R * b) % p
            t = (t * c) % p

        return R

    def __mul__(self, scalar: int) -> MGAffinePoint[C]:
        """
        Scalar multiplication using double-and-add algorithm.

        This implementation ensures consistency with the point addition formulas
        by using the same underlying operations.
        """
        if scalar == 0:
            return self.__class__(None, None)

        # Handle negative scalar
        if scalar < 0:
            return (-self) * (-scalar)

        if self.is_identity():
            return self.__class__(None, None)

        # Use double-and-add for consistency with point addition formulas
        return self._scalar_mult_double_add(scalar)

    def _scalar_mult_double_add(self, scalar: int) -> MGAffinePoint[C]:
        """
        Scalar multiplication using double-and-add algorithm.

        This implementation ensures consistency with the point addition formulas
        by using the same underlying operations.
        """
        if scalar == 0:
            return self.__class__(None, None)

        # Handle negative scalar
        if scalar < 0:
            return (-self)._scalar_mult_double_add(-scalar)

        if self.is_identity():
            return self.__class__(None, None)

        result = self.__class__(None, None)  # Start with identity
        current = self

        # Convert scalar to binary and process each bit
        while scalar > 0:
            if scalar & 1:
                # Add current point to result
                result = result + current
            # Double the current point
            current = current + current
            # Move to next bit
            scalar >>= 1

        return result

    def is_identity(self) -> bool:
        """Check if this is the identity element (point at infinity)."""
        return self.x is None or self.y is None

    def clear_cofactor(self) -> MGAffinePoint[C]:
        return self * self.curve.params.cofactor

    @classmethod
    def identity(cls) -> MGAffinePoint:
        """Get the identity element (point at infinity)."""
        return cls(None, None)

    @classmethod
    def encode_to_curve(
        cls,
        alpha_string: bytes,
        salt: bytes = b"",
    ) -> MGAffinePoint[C]:
        match cls.curve.e2c_variant:
            case E2C_Variant.ELL2_NU:
                return cls._encode_elligator2_nu(alpha_string, salt)
            case E2C_Variant.ELL2:
                return cls._encode_elligator2_ro(alpha_string, salt)
            case _:
                return super().encode_to_curve(alpha_string, salt)

    @classmethod
    def _encode_elligator2_nu(
        cls,
        alpha_string: bytes,
        salt: bytes = b"",
    ) -> MGAffinePoint[C]:
        """Encode with the nonuniform Elligator2 hash-to-curve variant."""
        string_to_hash = salt + alpha_string
        (u0,) = cls.curve.hash_to_field(string_to_hash, 1)
        return cls.map_to_curve(u0).clear_cofactor()

    @classmethod
    def _encode_elligator2_ro(
        cls,
        alpha_string: bytes,
        salt: bytes = b"",
    ) -> MGAffinePoint[C]:
        """Encode with the random-oracle Elligator2 hash-to-curve variant."""
        string_to_hash = salt + alpha_string
        u0, u1 = cls.curve.hash_to_field(string_to_hash, 2)
        q0 = cls.map_to_curve(u0)
        q1 = cls.map_to_curve(u1)
        R = q0 + q1
        return R.clear_cofactor()

    @classmethod
    def map_to_curve(cls, u: int) -> MGAffinePoint[C]:
        """
        Map a field element to a curve point using Elligator 2.

        Args:
            u: Field element to map

        Returns:
            TEAffinePoint: Resulting curve point
        """
        # 1.x1 = -(J / K) * inv0(1 + Z * u ^ 2)
        # 2.If x1 == 0, set x1 = -(J / K)
        # 3.gx1 = x1 ^ 3 + (J / K) * x1 ^ 2 + x1 / K ^ 2
        # 4.x2 = -x1 - (J / K)
        # 5.gx2 = x2 ^ 3 + (J / K) * x2 ^ 2 + x2 / K ^ 2
        # 6.If is_square(gx1), set x = x1, y = sqrt(gx1) with sgn0(y) == 1.
        # 7.Else set x = x2, y = sqrt(gx2) with sgn0(y) == 0.
        # 8.s = x * K
        # 9. t = y * K
        # 10.return (s, t)

        curve = cls.curve
        p = curve.params.field_modulus
        J = curve.params.a
        K = curve.params.b
        Z = cast(int, curve.params.hash_to_curve.z)

        c1 = (J * curve.mod_inverse(K)) % p
        c2 = curve.mod_inverse(K * K) % p

        # Main mapping computation
        tv1 = (Z * u * u) % p
        e1 = tv1 == -1
        tv1 = 0 if e1 else tv1

        x1 = (-c1 * curve.mod_inverse(tv1 + 1)) % p
        gx1 = (((x1 + c1) * x1 + c2) * x1) % p

        x2 = -x1 - c1
        gx2 = (tv1 * gx1) % p

        # Choose correct values
        e2 = curve.is_square(gx1)
        x = x2 if not e2 else x1
        y2 = gx2 if not e2 else gx1

        # Compute square root
        y = curve.mod_sqrt(y2)

        # Adjust sign
        e3 = (y & 1) == 1
        y = -y % p if e2 ^ e3 else y

        # Scale coordinates
        s = (x * K) % p
        t = (y * K) % p

        return cls(s, t)

    def point_to_string(self) -> bytes:
        if self.is_identity():
            raise ValueError("Cannot serialize point at infinity")
        p = self.curve.params.field_modulus
        field_byte_len = (p.bit_length() + 7) // 8

        if self.curve.params.encoding.uncompressed:
            # Encode u and v coordinates as little-endian bytes
            if self.x is None or self.y is None:
                raise ValueError("Cannot serialize identity point")
            x_bytes = self.x.to_bytes(field_byte_len, self.curve.params.encoding.endian)
            y_bytes = self.y.to_bytes(field_byte_len, self.curve.params.encoding.endian)
            return x_bytes + y_bytes
        else:
            raise NotImplementedError("Compressed encoding not implemented")

    @classmethod
    def string_to_point(cls, data: str | bytes) -> MGAffinePoint:
        if isinstance(data, str):
            data = bytes.fromhex(data)

        p = cls.curve.params.field_modulus
        byte_length = (p.bit_length() + 7) // 8
        if cls.curve.params.encoding.uncompressed:
            # Split into u and v coordinates
            u_bytes = data[:byte_length]
            v_bytes = data[byte_length:]

            u = int.from_bytes(u_bytes, cls.curve.params.encoding.endian)
            v = int.from_bytes(v_bytes, cls.curve.params.encoding.endian)

            # Create the point
            point = cls(u, v)

        else:
            ...

        # Verify the point is on the curve
        if not point.is_on_curve():
            raise ValueError("Point is not on the curve")

        return point

    @classmethod
    def _x_recover(cls, y: int) -> int:
        raise NotImplementedError("Must be implemented by subclass")
