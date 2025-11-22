from __future__ import annotations

from dataclasses import dataclass
from typing import Final, TypeVar, Generic, Type, Optional, Tuple, Any, Union
from ..point import CurvePoint, PointProtocol
from .mg_curve import MGCurve
from dot_ring.curve.e2c import E2C_Variant

C = TypeVar('C', bound=MGCurve)


@dataclass(frozen=True)
class MGAffinePoint(CurvePoint):
    """
    Affine point on a Montgomery curve.

    Notes:
      - Identity is represented by x=None, y=None.
      - _make_point tries constructor signatures (x,y,curve) and (x,y) and falls
        back to creating an instance directly if necessary.
      - Addition/doubling use canonical Montgomery affine formulas:
          lambda = (y2 - y1)/(x2 - x1)
          x3 = B*lambda^2 - A - x1 - x2
          y3 = lambda*(x1 - x3) - y1
        Doubling:
          lambda = (3*x1^2 + 2*A*x1 + 1) / (2*B*y1)
    """

    def _make_point(self, x: Optional[int], y: Optional[int]):
        """
        Helper to construct a new point instance in a robust way.

        Some subclasses accept (x, y, curve) and some (x, y). Try both; if both
        raise TypeError, build an instance bypassing __init__ and set attributes.
        """
        cls = self.__class__
        curve = self.curve
        try:
            # try (x, y, curve)
            return cls(x, y, curve)
        except TypeError:
            pass
        try:
            # try (x, y)
            return cls(x, y)
        except TypeError:
            pass

        # fallback: create without calling __init__ and set attributes directly
        inst = object.__new__(cls)
        object.__setattr__(inst, "x", x)
        object.__setattr__(inst, "y", y)
        object.__setattr__(inst, "curve", curve)
        return inst

    def is_on_curve(self) -> bool:
        """Check if point is on the curve."""
        # identity is considered on-curve by convention
        if self.is_identity():
            return True
        return self.curve.is_on_curve((self.x, self.y))

    def __add__(self, other: "MGAffinePoint[C]") -> "MGAffinePoint[C]":
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

        p = self.curve.PRIME_FIELD
        A = self.curve.A
        B = self.curve.B

        # ensure coords are ints mod p
        x1, y1 = self.x % p, self.y % p
        x2, y2 = other.x % p, other.y % p

        # Doubling
        if x1 == x2 and y1 == y2:
            # if y == 0 then slope denominator = 0 => result is identity
            if y1 % p == 0:
                return self._make_point(None, None)
            num = (3 * x1 * x1 + 2 * A * x1 + 1) % p
            den = (2 * B * y1) % p
            # Check if denominator is zero before computing inverse
            if den == 0:
                return self._make_point(None, None)
            lam = (num * pow(den, -1, p)) % p
            x3 = (B * (lam * lam % p) - A - 2 * x1) % p
            y3 = (lam * (x1 - x3) - y1) % p
            return self._make_point(x3, y3)

        # Addition for distinct points
        if x1 == x2:
            # vertical line -> identity (x1 == x2 but y1 != y2)
            return self._make_point(None, None)

        num = (y2 - y1) % p
        den = (x2 - x1) % p
        # Check if denominator is zero (shouldn't happen since x1 != x2)
        if den == 0:
            raise ValueError("Unexpected zero denominator in point addition")
        lam = (num * pow(den, -1, p)) % p
        # Corrected formula for x3 in point addition
        x3 = (B * lam * lam - A - x1 - x2) % p
        # Corrected formula for y3
        y3 = (lam * (x1 - x3) - y1) % p
        return self._make_point(x3, y3)

    def __neg__(self) -> "MGAffinePoint[C]":
        """Negate a point (x, y) -> (x, -y)."""
        if self.is_identity():
            return self._make_point(None, None)
        return self._make_point(self.x % self.curve.PRIME_FIELD, (-self.y) % self.curve.PRIME_FIELD)

    def __sub__(self, other: "MGAffinePoint[C]") -> "MGAffinePoint[C]":
        """Subtract points by adding the negation."""
        return self + (-other)

    def _sqrt_mod_p(self, n: int) -> Optional[int]:
        """
        Compute sqrt(n) mod p. Use p % 8 == 5 optimization if applicable, else
        Tonelli-Shanks.
        Returns one square root or None if none exists.
        """
        p = self.curve.PRIME_FIELD
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

    def __mul__(self, scalar: int) -> "MGAffinePoint[C]":
        """
        Scalar multiplication using double-and-add algorithm.

        This implementation ensures consistency with the point addition formulas
        by using the same underlying operations.
        """
        if scalar == 0:
            return self._make_point(None, None)

        # Handle negative scalar
        if scalar < 0:
            return (-self) * (-scalar)

        if self.is_identity():
            return self._make_point(None, None)

        # Use double-and-add for consistency with point addition formulas
        return self._scalar_mult_double_add(scalar)

    def _scalar_mult_double_add(self, scalar: int) -> "MGAffinePoint[C]":
        """
        Scalar multiplication using double-and-add algorithm.

        This implementation ensures consistency with the point addition formulas
        by using the same underlying operations.
        """
        if scalar == 0:
            return self._make_point(None, None)

        # Handle negative scalar
        if scalar < 0:
            return (-self)._scalar_mult_double_add(-scalar)

        if self.is_identity():
            return self._make_point(None, None)

        result = self._make_point(None, None)  # Start with identity
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

    def clear_cofactor(self)-> "MGAffinePoint[C]":
        return self*self.curve.COFACTOR

    @classmethod
    def identity(cls) -> "MGAffinePoint":
        """Get the identity element (point at infinity)."""
        # build without calling curve-specific __init__
        inst = object.__new__(cls)
        object.__setattr__(inst, "x", None)
        object.__setattr__(inst, "y", None)
        # use a curve instance if available via class attribute, else None
        # Many specific point classes set `curve` as a class attribute (see your Curve25519Point)
        curve = getattr(cls, "curve", None)
        object.__setattr__(inst, "curve", curve)
        return inst

    @classmethod
    def encode_to_curve(cls, alpha_string: bytes | str, salt: bytes | str = b"", General_Check:bool=False) -> "MGAffinePoint[C]"|Any:

        if not isinstance(alpha_string, bytes):
            alpha_string = bytes.fromhex(alpha_string)

        if not isinstance(salt, bytes):
            salt = bytes.fromhex(salt)

        # Check if it's an ELL2 variant (ELL2 or ELL2_NU)
        if cls.curve.E2C in (E2C_Variant.ELL2, E2C_Variant.ELL2_NU):
            if cls.curve.E2C.value.endswith("_NU_"):
                return cls.encode_to_curve_hash2_suite_nu(alpha_string, salt, General_Check)

            return cls.encode_to_curve_hash2_suite_ro(alpha_string, salt, General_Check)
        else:
            raise ValueError(f"Unexpected E2C Variant: {cls.curve.E2C}")

    @classmethod
    def encode_to_curve_hash2_suite_nu(cls, alpha_string: bytes, salt: bytes = b"",General_Check: bool = False) -> "MGAffinePoint[C]" | Any:
        """
        Encode a string to a curve point using Elligator 2.

        Args:
            alpha_string: String to encode
            salt: Optional salt for the encoding

        Returns:
            TEAffinePoint: Resulting curve point
        """
        string_to_hash = salt + alpha_string
        u = cls.curve.hash_to_field(string_to_hash, 1)
        R= cls.map_to_curve(u[0])  # ELL2
        if General_Check:
            P = R.clear_cofactor()
            return {
                "u": u,
                "Q0": [R.x, R.y],
                "P": [P.x, P.y]
            }
        return R.clear_cofactor()

    @classmethod
    def encode_to_curve_hash2_suite_ro(cls, alpha_string: bytes, salt: bytes = b"", General_Check:bool=False) -> "MGAffinePoint[C]"|Any:
        """
        Encode a string to a curve point using Elligator 2.

        Args:
            alpha_string: String to encode
            salt: Optional salt for the encoding

        Returns:
            TEAffinePoint: Resulting curve point
        """
        string_to_hash = salt + alpha_string
        u = cls.curve.hash_to_field(string_to_hash, 2)

        q0 = cls.map_to_curve(u[0])  # ELL2
        q1 = cls.map_to_curve(u[1])  # ELL2
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



    def clear_cofactor(self) -> "MGAffinePoint[C]":
        """
        Clear the cofactor to ensure point is in prime-order subgroup.

        Returns:
            TEAffinePoint: Point in prime-order subgroup
        """
        return self * self.curve.COFACTOR

    @classmethod
    def map_to_curve(cls, u: int) -> "MGAffinePoint[C]":
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

        p = cls.curve.PRIME_FIELD
        J= cls.curve.A
        K= cls.curve.B
        Z = cls.curve.Z

        c1 = (J * cls.curve.mod_inverse(K)) % p
        c2 = cls.curve.mod_inverse(K * K) % p

        # Main mapping computation
        tv1 = (Z * u * u) % p
        e1 = tv1 == -1
        tv1 = 0 if e1 else tv1

        x1 = (-c1 * cls.curve.mod_inverse(tv1 + 1)) % p
        gx1 = (((x1 + c1) * x1 + c2) * x1) % p

        x2 = (-x1 - c1) % p
        gx2 = (tv1 * gx1) % p

        # Choose correct values
        e2 = cls.curve.is_square(gx1)
        x = x2 if not e2 else x1
        y2 = gx2 if not e2 else gx1

        # Compute square root
        y = cls.curve.mod_sqrt(y2)

        # Adjust sign
        e3 = (y & 1) == 1
        y = -y % p if e2 ^ e3 else y

        # Scale coordinates
        s = (x * K) % p
        t = (y * K) % p

        return cls(s, t, cls.curve)

    def point_to_string(self) -> bytes:

        if self.is_identity():
            raise ValueError("Cannot serialize point at infinity")
        p = self.curve.PRIME_FIELD
        byte_length = (p.bit_length() + 7) // 8

        if self.curve.UNCOMPRESSED:
            # Encode u and v coordinates as little-endian bytes
            u_bytes = self.x.to_bytes(byte_length, 'little')
            v_bytes = self.y.to_bytes(byte_length, 'little')
            return u_bytes + v_bytes
        else:
            ...

    @classmethod
    def string_to_point(cls, data: Union[str, bytes]) -> 'MGAffinePoint':
        if isinstance(data, str):
            data = bytes.fromhex(data)
            
        p = cls.curve.PRIME_FIELD
        byte_length = (p.bit_length() + 7) // 8
        if cls.curve.UNCOMPRESSED:
            # Split into u and v coordinates
            u_bytes = data[:byte_length]
            v_bytes = data[byte_length:]

            u = int.from_bytes(u_bytes, 'little')
            v = int.from_bytes(v_bytes, 'little')

            # Create the point
            point = cls(u, v, cls.curve)

        else:
            ...

        # Verify the point is on the curve
        if not point.is_on_curve():
            raise ValueError("Point is not on the curve")
            
        return point