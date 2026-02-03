from __future__ import annotations

import hashlib
from typing import Any, Self, TypeVar, cast

from dot_ring.curve.e2c import E2C_Variant

from ..point import CurvePoint
from .te_curve import TECurve

C = TypeVar("C", bound=TECurve)


class TEAffinePoint(CurvePoint[C]):
    """
    Twisted Edwards Curve Point in Affine Coordinates.

    This class implements point operations on a Twisted Edwards curve using affine coordinates.
    Twisted Edwards curve have the form: ax² + y² = 1 + dx²y²

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
        Check if this is the identity element (point at infinity).
        The identity point is represented with None coordinates.

        Returns:
            bool: True if this is the identity element
        """
        return self.x == 0 and self.y == 1

    @classmethod
    def identity(cls) -> Self:
        """
        Get the identity element (point at infinity).

        Returns:
            SWAffinePoint: Identity element
        """
        # Return a identity point (0, 1)
        return cls(0, 1)

    def is_on_curve(self) -> bool:
        """
        Check if point lies on the Twisted Edwards curve.

        Returns:
            bool: True if point satisfies curve equation
        """
        # ax² + y² = 1 + dx²y²
        v, w = cast(int, self.x), cast(int, self.y)
        p = self.curve.PRIME_FIELD

        lhs = (self.curve.EdwardsA * pow(v, 2, p) + pow(w, 2, p)) % p
        rhs = (1 + self.curve.EdwardsD * pow(v, 2, p) * pow(w, 2, p)) % p
        return lhs == rhs

    def __add__(self, other: CurvePoint[C]) -> Self:
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

        if self == other:
            res = self.double()
            return cast(Any, res)  # type: ignore

        if self == self.identity_point():
            return cast(Self, other)

        if other == self.identity_point():
            return self

        p = self.curve.PRIME_FIELD
        if self.x is None or self.y is None or other.x is None or other.y is None:
            raise ValueError("Unexpected identity point in addition")
        x1, y1 = cast(int, self.x), cast(int, self.y)
        x2, y2 = cast(int, other.x), cast(int, other.y)

        # Compute intermediate values
        x1y2 = (x1 * y2) % p
        x2y1 = (x2 * y1) % p
        y1y2 = (y1 * y2) % p
        x1x2 = (x1 * x2) % p
        dx1x2y1y2 = (self.curve.EdwardsD * x1x2 * y1y2) % p

        # Compute result coordinates
        x3 = ((x1y2 + x2y1) * pow(1 + dx1x2y1y2, -1, self.curve.PRIME_FIELD)) % p
        y3 = ((y1y2 - self.curve.EdwardsA * x1x2) * pow(1 - dx1x2y1y2, -1, self.curve.PRIME_FIELD)) % p

        return self.__class__(x3, y3)

    def __neg__(self) -> Self:
        """
        Negate a point.

        Returns:
            TEAffinePoint: Negated point
        """
        return self.__class__(-cast(int, self.x) % self.curve.PRIME_FIELD, self.y)

    def __sub__(self, other: CurvePoint[C]) -> Self:
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
        x1, y1 = cast(int, self.x), cast(int, self.y)
        p = self.curve.PRIME_FIELD

        # Check for identity point
        if y1 == 0:
            return self.identity_point()

        # Calculate denominators
        denom_x = (self.curve.EdwardsA * x1**2 + y1**2) % p
        denom_y = (2 - self.curve.EdwardsA * x1**2 - y1**2) % p

        if denom_x == 0 or denom_y == 0:
            return self.identity_point()

        # Calculate new coordinates
        x3 = (2 * x1 * y1 * pow(denom_x, -1, self.curve.PRIME_FIELD)) % p
        y3 = ((y1**2 - self.curve.EdwardsA * x1**2) * pow(denom_y, -1, self.curve.PRIME_FIELD)) % p

        return self.__class__(x3, y3)

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
        scalar = scalar % self.curve.ORDER

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
    def identity_point(cls) -> Self:
        """
        Get the identity point (0, 1) of the curve.

        Returns:
            TEAffinePoint: Identity point
        """
        return cls(0, 1)

    @classmethod
    def encode_to_curve(
        cls,
        alpha_string: bytes | str,
        salt: bytes | str = b"",
        General_Check: bool = False,
    ) -> Self | Any:
        if not isinstance(alpha_string, bytes):
            alpha_string = bytes.fromhex(alpha_string)

        if not isinstance(salt, bytes):
            salt = bytes.fromhex(salt)

        if cls.curve.E2C in [E2C_Variant.ELL2, E2C_Variant.ELL2_NU]:
            if cls.curve.E2C.value.endswith("_NU_"):
                return cls.encode_to_curve_hash2_suite_nu(alpha_string, salt, General_Check)
            return cls.encode_to_curve_hash2_suite_ro(alpha_string, salt, General_Check)
        elif cls.curve.E2C == E2C_Variant.TAI:
            return cls.encode_to_curve_tai(alpha_string, salt)
        else:
            raise ValueError("Unexpected E2C Variant")

    @classmethod
    def encode_to_curve_hash2_suite_ro(cls, alpha_string: bytes, salt: bytes = b"", General_Check: bool = False) -> Self | Any:
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
            P = R.clear_cofactor()
            return {"u": u, "Q0": [q0.x, q0.y], "Q1": [q1.x, q1.y], "P": [P.x, P.y]}
        return R.clear_cofactor()

    @classmethod
    def encode_to_curve_hash2_suite_nu(cls, alpha_string: bytes, salt: bytes = b"", General_Check: bool = False) -> Self | Any:
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
        R = cls.map_to_curve(u[0])  # ELL2
        if General_Check:
            P = R.clear_cofactor()
            return {"u": u, "Q0": [R.x, R.y], "P": [P.x, P.y]}
        return R.clear_cofactor()

    @classmethod  # modified
    def encode_to_curve_tai(cls, alpha_string: bytes | str, salt: bytes = b"") -> Self:
        """
        Encode a string to a curve point using try-and-increment method for ECVRF.

        Args:
            alpha_string:String to encode
            salt: Optional salt for the encoding

        Returns:
            TEAffinePoint: Resulting curve point
        """
        ctr = 0
        H: Self | str = "INVALID"
        front = b"\x01"
        back = b"\x00"
        alpha_string = alpha_string.encode() if isinstance(alpha_string, str) else alpha_string
        salt = salt.encode() if isinstance(salt, str) else salt
        suite_string = cls.curve.SUITE_STRING
        while H == "INVALID" or H == cls.identity_point():
            ctr_string = ctr.to_bytes(1, "big")
            hash_input = suite_string + front + salt + alpha_string + ctr_string + back
            hash_output = hashlib.sha512(hash_input).digest()
            H = cls.string_to_point(hash_output[:32])
            if isinstance(H, TEAffinePoint) and cls.curve.COFACTOR > 1:
                H = H.clear_cofactor()
            ctr += 1
        return cast(Self, H)

    def clear_cofactor(self) -> Self:
        """
        Clear the cofactor to ensure point is in prime-order subgroup.

        Returns:
            TEAffinePoint: Point in prime-order subgroup
        """
        return self * (self.curve.COFACTOR)

    @classmethod
    def map_to_curve(cls, u: int) -> Self:
        """
        Map a field element to a curve point using Elligator 2.

        Args:
            u: Field element to map

        Returns:
            TEAffinePoint: Resulting curve point
        """

        s, t = cls.curve.map_to_curve_ell2(u)
        return cls.from_mont(s, t)

    @classmethod
    def from_mont(cls, s: int, t: int) -> Self:
        """
        Convert from Montgomery to Twisted Edwards coordinates.

        Args:
            s: Montgomery s-coordinate
            t: Montgomery t-coordinate

        Returns:
            TEAffinePoint: Point in Twisted Edwards coordinates
        """
        field = cls.curve.PRIME_FIELD

        # Convert coordinates
        tv1 = (s + 1) % field
        tv2 = (tv1 * t) % field

        try:
            tv2 = pow(tv2, -1, cls.curve.PRIME_FIELD)
        except ValueError:
            tv2 = 0

        v = (tv2 * tv1 * s) % field
        w = (tv2 * t * (s - 1)) % field

        # Handle exceptional case
        w = 1 if tv2 == 0 else w

        return cls(v, w)

    @classmethod
    def _x_recover(cls, y: int) -> int | tuple[int, int] | None:
        """ """
        p = cls.curve.PRIME_FIELD
        lhs = (1 - y * y) % p
        rhs = (cls.curve.EdwardsA - cls.curve.EdwardsD * y * y) % p

        try:
            inv_rhs = pow(rhs, -1, p)
        except ValueError:
            return None

        x2 = (lhs * inv_rhs) % p
        try:
            x = cls.curve.mod_sqrt(x2)
        except ValueError:
            return None

        neg_x = (-x) % p
        # consistent ordering
        return (x, neg_x) if x <= neg_x else (neg_x, x)
