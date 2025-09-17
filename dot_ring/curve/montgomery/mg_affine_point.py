from __future__ import annotations

from dataclasses import dataclass
from typing import Final, TypeVar, Generic, Type, Optional, Tuple
from ..point import Point, PointProtocol
from .mg_curve import MGCurve

C = TypeVar('C', bound=MGCurve)


@dataclass(frozen=True)
class MGAffinePoint(Point[C]):
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
        try:
            a24 = ((A + 2) * pow(4, -1, p)) % p
        except ValueError:
            raise ValueError("Cannot compute (A+2)/4 mod p - invalid curve parameters")

        # Call ladder_step implemented by MGCurve
        try:
            x_result = self.curve.ladder_step(u, a24, scalar)
        except AttributeError:
            # Fallback to simple double-and-add if ladder_step not available
            return self._scalar_mult_double_add(scalar)
        except ZeroDivisionError:
            # ladder reported point-at-infinity (Z==0)
            return self._make_point(None, None)
        except Exception as e:
            # Handle other ladder errors
            raise RuntimeError(f"Error in ladder_step: {e}")

        x_result %= p

        # Reconstruct v^2 = (x^3 + A x^2 + x) / B
        try:
            invB = pow(B, -1, p)
        except ValueError:
            raise ValueError("B is not invertible mod p - invalid curve")

        x_cubed = (x_result * x_result % p) * x_result % p
        x_squared = x_result * x_result % p
        numerator = (x_cubed + (A * x_squared) % p + x_result) % p
        v_sq = (numerator * invB) % p

        # Check quadratic residuosity
        if pow(v_sq, (p - 1) // 2, p) != 1:
            # This might happen due to sign ambiguity in ladder
            # Try the other square root or return identity
            return self._make_point(None, None)

        v = self._sqrt_mod_p(v_sq)
        if v is None:
            raise ValueError("Tonelli-Shanks failed to find square root (unexpected)")

        # Choose canonical sign for y — make it even LSB deterministically
        if v & 1:
            v = (-v) % p

        return self._make_point(x_result, v)

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

    def to_bytes(self, compressed: bool = True) -> bytes:
        """
        Convert point to bytes representation.
        For Montgomery curves like Curve25519, typically only x-coordinate is used.
        """
        if self.is_identity():
            # Return zero bytes for identity
            byte_length = (self.curve.PRIME_FIELD.bit_length() + 7) // 8
            return b'\x00' * byte_length

        x_bytes = self.x.to_bytes((self.curve.PRIME_FIELD.bit_length() + 7) // 8, 'little')

        if compressed or not hasattr(self, 'y') or self.y is None:
            return x_bytes
        else:
            # Include y-coordinate if requested and available
            y_bytes = self.y.to_bytes((self.curve.PRIME_FIELD.bit_length() + 7) // 8, 'little')
            return x_bytes + y_bytes

    @classmethod
    def from_bytes(cls, data: bytes, curve, compressed: bool = True):
        """
        Create point from bytes representation.
        """
        if not data or all(b == 0 for b in data):
            return cls.identity()

        byte_length = (curve.PRIME_FIELD.bit_length() + 7) // 8

        if len(data) < byte_length:
            raise ValueError(f"Data too short: expected at least {byte_length} bytes")

        x = int.from_bytes(data[:byte_length], 'little')

        if compressed or len(data) == byte_length:
            # Reconstruct y-coordinate
            # For Montgomery curves: B*y^2 = x^3 + A*x^2 + x
            A, B = curve.A, curve.B
            p = curve.PRIME_FIELD

            x = x % p
            rhs = (x * x * x + A * x * x + x) % p

            # Check if B has an inverse
            try:
                inv_B = pow(B, -1, p)
                y_squared = (rhs * inv_B) % p
            except ValueError:
                raise ValueError("Invalid curve: B not invertible")

            # Find square root
            inst = object.__new__(cls)
            object.__setattr__(inst, "curve", curve)
            y = inst._sqrt_mod_p(y_squared)

            if y is None:
                raise ValueError("Point not on curve")

            # Choose canonical y (even LSB)
            if y & 1:
                y = (-y) % p

            return cls(x, y, curve)
        else:
            # Uncompressed format with y-coordinate
            if len(data) < 2 * byte_length:
                raise ValueError(f"Data too short for uncompressed: expected {2 * byte_length} bytes")

            y = int.from_bytes(data[byte_length:2 * byte_length], 'little')
            point = cls(x, y, curve)

            if not point.is_on_curve():
                raise ValueError("Point not on curve")

            return point

    @classmethod
    def encode_to_curve(cls, alpha_string: bytes | str, salt: bytes | str = b"") -> "MGAffinePoint[C]":

        if not isinstance(alpha_string, bytes):
            alpha_string = bytes.fromhex(alpha_string)

        if not isinstance(salt, bytes):
            salt = bytes.fromhex(salt)

        if cls.curve.E2C == E2C_Variant.ELL2:
            return cls.encode_to_curve_hash2_suite(alpha_string, salt)
        else:
            raise ValueError("Unexpected E2C Variant")

    @classmethod
    def encode_to_curve_hash2_suite(cls, alpha_string: bytes, salt: bytes = b"") -> "MGAffinePoint[C]":
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
        s, t = cls.curve.map_to_curve_ell2(u)
        return cls(s,t)
