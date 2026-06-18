from __future__ import annotations

from typing import Any, Self, TypeVar, cast

from gmpy2 import invert as _invert
from gmpy2 import mpz as _mpz

from dot_ring.curve.e2c import E2C_Variant

from ..point import CurvePoint
from .te_curve import TECurve

C = TypeVar("C", bound=TECurve)


class TEAffinePoint(CurvePoint[C, int]):
    """
    Twisted Edwards Curve Point in Affine Coordinates.

    This class implements point operations on a Twisted Edwards curve using affine coordinates.
    Twisted Edwards curves have the form: ax² + y² = 1 + dx²y².

    Attributes:
        x: x-coordinate
        y: y-coordinate
        curve: The Twisted Edwards curve this point belongs to
    """

    def __post_init__(self) -> None:
        """Validate point after initialization."""
        super().__post_init__()
        if not isinstance(self.curve, TECurve):
            raise TypeError("Curve must be a Twisted Edwards curve")

    def is_identity(self) -> bool:
        """
        Check if this is the Twisted Edwards identity element.

        Returns:
            bool: True if this is the identity element
        """
        return self.x == 0 and self.y == 1

    @classmethod
    def identity(cls, curve: C) -> Self:
        """
        Get the Twisted Edwards identity element.

        Returns:
            TEAffinePoint: Identity element
        """
        return cls(0, 1, curve)

    def is_on_curve(self) -> bool:
        """
        Check if point lies on the Twisted Edwards curve.

        Returns:
            bool: True if point satisfies curve equation
        """
        # ax² + y² = 1 + dx²y²
        v, w = cast(int, self.x), cast(int, self.y)
        p = self.curve.params.field_modulus

        lhs = (self.curve.params.a * pow(v, 2, p) + pow(w, 2, p)) % p
        rhs = (1 + self.curve.params.d * pow(v, 2, p) * pow(w, 2, p)) % p
        return lhs == rhs

    def __add__(self, other: CurvePoint[C, int]) -> Self:
        """
        Add two points using Twisted Edwards addition formulas.

        Args:
            other: Point to add

        Returns:
            TEAffinePoint: Result of addition

        Raises:
            TypeError: If other is not a TEAffinePoint
        """
        if not isinstance(other, TEAffinePoint):
            raise TypeError("Can only add TEAffinePoints")

        if self.is_identity():
            return cast(Self, other)

        if other.is_identity():
            return self

        if self == other:
            return self.double()

        if self.x is None or self.y is None or other.x is None or other.y is None:
            raise ValueError("Unexpected identity point in addition")

        p = _mpz(self.curve.params.field_modulus)
        a_coeff = _mpz(self.curve.params.a) % p
        d_coeff = _mpz(self.curve.params.d) % p
        x1, y1 = _mpz(cast(int, self.x)) % p, _mpz(cast(int, self.y)) % p
        x2, y2 = _mpz(cast(int, other.x)) % p, _mpz(cast(int, other.y)) % p

        # Twisted Edwards addition law:
        # x3 = (x1*y2 + x2*y1) / (1 + d*x1*x2*y1*y2)
        # y3 = (y1*y2 - a*x1*x2) / (1 - d*x1*x2*y1*y2)
        x1y2 = (x1 * y2) % p
        x2y1 = (x2 * y1) % p
        y1y2 = (y1 * y2) % p
        x1x2 = (x1 * x2) % p
        dx1x2y1y2 = (d_coeff * x1x2 * y1y2) % p

        x3 = ((x1y2 + x2y1) * _invert(1 + dx1x2y1y2, p)) % p
        y3 = ((y1y2 - a_coeff * x1x2) * _invert(1 - dx1x2y1y2, p)) % p
        return self.__class__(int(x3), int(y3), self.curve)

    def __neg__(self) -> Self:
        """
        Negate a point.

        Returns:
            TEAffinePoint: Negated point
        """
        x = -cast(int, self.x) % self.curve.params.field_modulus
        return self.__class__(x, self.y, self.curve)

    def __sub__(self, other: CurvePoint[C, int]) -> Self:
        """
        Subtract two points.

        Args:
            other: Point to subtract

        Returns:
            TEAffinePoint: Result of subtraction
        """
        return cast(Self, self + (-cast(Any, other)))

    def double(self) -> Self:
        """
        Double a point using specialized doubling formulas.

        Returns:
            TEAffinePoint: 2P
        """
        p = _mpz(self.curve.params.field_modulus)
        a_coeff = _mpz(self.curve.params.a) % p
        x1, y1 = _mpz(cast(int, self.x)) % p, _mpz(cast(int, self.y)) % p

        if y1 == 0:
            return self.identity(self.curve)

        # Specialized affine doubling formulas for twisted Edwards curves.
        denom_x = (a_coeff * x1**2 + y1**2) % p
        denom_y = (2 - a_coeff * x1**2 - y1**2) % p

        if denom_x == 0 or denom_y == 0:
            return self.identity(self.curve)

        x3 = (2 * x1 * y1 * _invert(denom_x, p)) % p
        y3 = ((y1**2 - a_coeff * x1**2) * _invert(denom_y, p)) % p
        return self.__class__(int(x3), int(y3), self.curve)

    def __mul__(self, scalar: int) -> Self:
        """
        Basic double-and-add scalar multiplication.

        Args:
            scalar: Integer to multiply by

        Returns:
            TEAffinePoint: Scalar multiplication result
        """
        from .te_projective_point import TEProjectivePoint

        P_proj: Any = TEProjectivePoint.from_affine(self)
        result = TEProjectivePoint.zero(self.curve)
        addend = P_proj
        scalar = scalar % self.curve.params.subgroup_order

        while scalar:
            if scalar & 1:
                result = result + addend
            addend = addend.double()
            scalar >>= 1

        return cast(Self, result.to_affine(self.__class__))

    def __rmul__(self, scalar: int) -> Self:
        """
        Support scalar multiplication where scalar is on the left (scalar * point).
        """
        return self.__mul__(scalar)

    @classmethod
    def encode_to_curve(
        cls,
        alpha_string: bytes | str,
        salt: bytes | str = b"",
        curve: C | None = None,
    ) -> Self:
        """
        Encode input bytes to a point using the curve's configured hash-to-curve variant.
        """
        if curve is None:
            raise ValueError("curve is required")
        if not isinstance(alpha_string, bytes):
            alpha_string = bytes.fromhex(alpha_string)

        if not isinstance(salt, bytes):
            salt = bytes.fromhex(salt)

        if curve.e2c_variant == E2C_Variant.TAI:
            from dot_ring.vrf.transcript import hash_to_curve_tai

            return cast(Self, hash_to_curve_tai(cls, salt + alpha_string, curve))

        if curve.e2c_variant in (E2C_Variant.ELL2, E2C_Variant.ELL2_NU):
            if curve.e2c_variant.value.endswith("_NU_"):
                return cls._encode_elligator2_nu(alpha_string, curve, salt)
            return cls._encode_elligator2_ro(alpha_string, curve, salt)

        raise ValueError("Unexpected E2C Variant")

    @classmethod
    def _encode_elligator2_ro(
        cls,
        alpha_string: bytes,
        curve: C,
        salt: bytes = b"",
    ) -> Self:
        """Encode with the random-oracle Elligator2 hash-to-curve variant."""
        string_to_hash = salt + alpha_string
        u0, u1 = curve.hash_to_field(string_to_hash, 2)
        q0 = cls.map_to_curve(u0, curve)
        q1 = cls.map_to_curve(u1, curve)
        return (q0 + q1).clear_cofactor()

    @classmethod
    def _encode_elligator2_nu(
        cls,
        alpha_string: bytes,
        curve: C,
        salt: bytes = b"",
    ) -> Self:
        """Encode with the nonuniform Elligator2 hash-to-curve variant."""
        string_to_hash = salt + alpha_string
        (u0,) = curve.hash_to_field(string_to_hash, 1)
        return cls.map_to_curve(u0, curve).clear_cofactor()

    def clear_cofactor(self) -> Self:
        """
        Clear the cofactor to ensure point is in prime-order subgroup.

        Returns:
            TEAffinePoint: Point in prime-order subgroup
        """
        cofactor = self.curve.params.cofactor
        if cofactor == 1:
            return self
        if cofactor > 0 and cofactor & (cofactor - 1) == 0:
            result = self
            for _ in range(cofactor.bit_length() - 1):
                result = result.double()
            return result
        return self * cofactor

    @classmethod
    def map_to_curve(cls, u: int, curve: C) -> Self:
        """
        Map a field element to a curve point using Elligator 2.

        Args:
            u: Field element to map

        Returns:
            TEAffinePoint: Resulting curve point
        """

        s, t = curve.map_to_curve_ell2(u)
        return cls.from_mont(s, t, curve)

    @classmethod
    def from_mont(cls, s: int, t: int, curve: C) -> Self:
        """
        Convert from Montgomery to Twisted Edwards coordinates.

        Args:
            s: Montgomery s-coordinate
            t: Montgomery t-coordinate

        Returns:
            TEAffinePoint: Point in Twisted Edwards coordinates
        """
        field = curve.params.field_modulus
        tv1 = (s + 1) % field
        tv2 = (tv1 * t) % field

        try:
            tv2 = pow(tv2, -1, field)
        except ValueError:
            tv2 = 0

        v = (tv2 * tv1 * s) % field
        w = (tv2 * t * (s - 1)) % field

        # Handle exceptional case
        w = 1 if tv2 == 0 else w

        return cls(v, w, curve)

    @classmethod
    def _x_recover(cls, y: int, curve: C) -> int | tuple[int, int] | None:
        """Recover the possible x-coordinates for a compressed Edwards y-coordinate."""
        p = curve.params.field_modulus
        lhs = (1 - y * y) % p
        rhs = (curve.params.a - curve.params.d * y * y) % p

        if rhs == 0:
            return None
        inv_rhs = int(_invert(_mpz(rhs), _mpz(p)))

        x2 = (lhs * inv_rhs) % p
        try:
            x = curve.mod_sqrt(x2)
        except ValueError:
            return None

        neg_x = (-x) % p
        # Return candidates in a deterministic order; decoding chooses by sign bit.
        return (x, neg_x) if x <= neg_x else (neg_x, x)
