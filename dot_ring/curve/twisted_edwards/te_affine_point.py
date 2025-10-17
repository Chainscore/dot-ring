from __future__ import annotations
import hashlib
import math
from dataclasses import dataclass
from typing import TypeVar, Self, Any, Tuple
from sympy import mod_inverse

from dot_ring.curve.e2c import E2C_Variant
from ..point import Point, PointProtocol
from .te_curve import TECurve


C = TypeVar("C", bound=TECurve)


@dataclass(frozen=True)
class TEAffinePoint(Point[C]):
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

    def is_on_curve(self) -> bool:
        """
        Check if point lies on the Twisted Edwards curve.

        Returns:
            bool: True if point satisfies curve equation
        """
        # ax² + y² = 1 + dx²y²
        v, w = self.x, self.y
        p = self.curve.PRIME_FIELD

        lhs = (self.curve.EdwardsA * pow(v, 2, p) + pow(w, 2, p)) % p
        rhs = (1 + self.curve.EdwardsD * pow(v, 2, p) * pow(w, 2, p)) % p
        return lhs == rhs

    def __add__(self, other: PointProtocol[C]) -> Self:
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
            return self.double()

        if self == self.identity_point():
            return other

        if other == self.identity_point():
            return self

        p = self.curve.PRIME_FIELD
        x1, y1 = self.x, self.y
        x2, y2 = other.x, other.y

        # Compute intermediate values
        x1y2 = (x1 * y2) % p
        x2y1 = (x2 * y1) % p
        y1y2 = (y1 * y2) % p
        x1x2 = (x1 * x2) % p
        dx1x2y1y2 = (self.curve.EdwardsD * x1x2 * y1y2) % p

        # Compute result coordinates
        x3 = ((x1y2 + x2y1) * self.curve.mod_inverse(1 + dx1x2y1y2)) % p
        y3 = (
                     (y1y2 - self.curve.EdwardsA * x1x2) * self.curve.mod_inverse(1 - dx1x2y1y2)
             ) % p

        return self.__class__(x3, y3)

    def __neg__(self) -> Self:
        """
        Negate a point.

        Returns:
            TEAffinePoint: Negated point
        """
        return self.__class__(-self.x % self.curve.PRIME_FIELD, self.y)

    def __sub__(self, other: PointProtocol[C]) -> Self:
        """
        Subtract two points.

        Args:
            other: Point to subtract

        Returns:
            TEAffinePoint: Result of subtraction
        """
        return self + (-other)

    def double(self) -> Self:
        """
        Double a point using specialized doubling formulas.

        Returns:
            TEAffinePoint: 2P
        """
        x1, y1 = self.x, self.y
        p = self.curve.PRIME_FIELD

        # Check for identity point
        if y1 == 0:
            return self.identity_point()

        # Calculate denominators
        denom_x = (self.curve.EdwardsA * x1 ** 2 + y1 ** 2) % p
        denom_y = (2 - self.curve.EdwardsA * x1 ** 2 - y1 ** 2) % p

        if denom_x == 0 or denom_y == 0:
            return self.identity_point()

        # Calculate new coordinates
        x3 = (2 * x1 * y1 * self.curve.mod_inverse(denom_x)) % p
        y3 = (
                     (y1 ** 2 - self.curve.EdwardsA * x1 ** 2) * self.curve.mod_inverse(denom_y)
             ) % p

        return self.__class__(x3, y3)

    def __mul__(self, scalar: int) -> Self:
        """
        Scalar multiplication using either GLV or double-and-add.

        Args:
            scalar: Integer to multiply by

        Returns:
            TEAffinePoint: Scalar multiplication result
        """
        if self.curve.glv.is_enabled:
            return self.glv_mul(scalar)
        return self.scalar_mul(scalar)


    def scalar_mul(self, scalar: int) -> Self:
        """
        Basic double-and-add scalar multiplication.

        Args:
            scalar: Integer to multiply by

        Returns:
            TEAffinePoint: Scalar multiplication result
        """
        result = self.identity_point()
        addend = self
        scalar = scalar % self.curve.ORDER

        while scalar:
            if scalar & 1:
                result = result + addend
            addend = addend.double()
            scalar >>= 1

        return result

    # def glv_mul(self, scalar: int) -> Self:
    #     """
    #     GLV scalar multiplication using endomorphism.
    #
    #     Args:
    #         scalar: Integer to multiply by
    #
    #     Returns:
    #         TEAffinePoint: Scalar multiplication result
    #     """
    #     n = self.curve.ORDER
    #     k1, k2 = self.curve.glv.decompose_scalar(scalar % n, n)
    #     phi = self.compute_endomorphism()
    #
    #     return self.scalar_mul(k1) + phi.scalar_mul(k2)

    def glv_mul(self, scalar: int) -> Self:
        """
        GLV scalar multiplication using endomorphism.

        Args:
            scalar: Integer to multiply by

        Returns:
            TEAffinePoint: Scalar multiplication result
        """
        n = self.curve.ORDER
        k1, k2 = self.curve.glv.decompose_scalar(scalar % n, n)
        phi = self.compute_endomorphism()

        return self.windowed_simultaneous_mult(k1, k2, self, phi, w=2)

    def windowed_simultaneous_mult(
            self,
            k1: int,
            k2: int,
            P1: PointProtocol[C],
            P2: PointProtocol[C],
            w: int = 2
    ) -> Self:
        """
        Compute k1 * P1 + k2 * P2 using windowed simultaneous multi-scalar multiplication.

        Args:
            k1: First scalar
            k2: Second scalar
            P1: First point
            P2: Second point
            w: Window size (default=2)

        Returns:
            TEAffinePoint: Result of k1*P1 + k2*P2

        Raises:
            TypeError: If P1 or P2 is not compatible with this curve
        """
        # Validate input points
        if not isinstance(P1, TEAffinePoint) or not isinstance(P2, TEAffinePoint):
            raise TypeError("Points must be TEAffinePoints")

        if P1.curve != self.curve or P2.curve != self.curve:
            raise ValueError("Points must be on the same curve")

        def split_scalar(scalar: int, width: int, chunks: int) -> list[int]:
            """Split scalar into 'chunks' groups of 'width' bits."""
            mask = (1 << width) - 1
            return [(scalar >> (i * width)) & mask for i in range(chunks)]

        # Step 1: Precompute all i*P1 + j*P2
        table = {}
        identity = self.identity_point()

        for i in range(1 << w):
            Pi = P1.scalar_mul(i) if i != 0 else identity
            for j in range(1 << w):
                Qj = P2.scalar_mul(j) if j != 0 else identity
                table[(i, j)] = Pi + Qj

        # Step 2: Split k1 and k2 into w-bit windows
        max_len = max(k1.bit_length(), k2.bit_length())
        d = math.ceil(max_len / w)
        k1_windows = split_scalar(k1, w, d)
        k2_windows = split_scalar(k2, w, d)

        # Step 3: Initialize result
        R = identity

        # Step 4: Iterate windows from MSB to LSB
        for i in range(d - 1, -1, -1):
            for _ in range(w):
                R = R.double()

            idx = (k1_windows[i], k2_windows[i])
            if idx in table:
                R = R + table[idx]

        return R

    def compute_endomorphism(self) -> Self:
        """
        Compute the GLV endomorphism of this point.

        Returns:
            TEAffinePoint: Result of endomorphism
        """
        p = self.curve.PRIME_FIELD
        # These constants should ideally be curve attributes
        B = 0x52c9f28b828426a561f00d3a63511a882ea712770d9af4d6ee0f014d172510b4
        C = 0x6cc624cf865457c3a97c6efd6c17d1078456abcfff36f4e9515c806cdf650b3d

        x, y = self.x, self.y
        y2 = pow(y, 2, p)
        xy = (x * y) % p
        f_y = (C * (1 - y2)) % p
        g_y = (B * (y2 + B)) % p
        h_y = (y2 - B) % p

        x_p = (f_y * h_y) % p
        y_p = (g_y * xy) % p
        z_p = (h_y * xy) % p

        x_a = (x_p * mod_inverse(z_p, p)) % p
        y_a = (y_p * mod_inverse(z_p, p)) % p

        return self.__class__(x_a, y_a)

    def identity_point(self) -> Self:
        """
        Get the identity point (0, 1) of the curve.

        Returns:
            TEAffinePoint: Identity point
        """
        return self.__class__(0, 1)

    @classmethod
    def encode_to_curve(cls, alpha_string: bytes|str, salt: bytes|str = b"", General_Check:bool=False) -> Self|Any:

        if not isinstance(alpha_string, bytes):
            alpha_string=bytes.fromhex(alpha_string)

        if not isinstance(salt, bytes):
            salt=bytes.fromhex(salt)

        if cls.curve.E2C in [E2C_Variant.ELL2,E2C_Variant.ELL2_NU]:
            if cls.curve.E2C.value.endswith("_NU_"):
                return cls.encode_to_curve_hash2_suite_nu(alpha_string, salt, General_Check)
            return cls.encode_to_curve_hash2_suite_ro(alpha_string, salt, General_Check)
        elif cls.curve.E2C == E2C_Variant.TAI:
            return cls.encode_to_curve_tai(alpha_string, salt)
        else:
            raise ValueError("Unexpected E2C Variant")

    @classmethod
    def encode_to_curve_hash2_suite_ro(cls, alpha_string: bytes, salt: bytes = b"", General_Check:bool=False) -> Self|Any:
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
        q0 = cls.map_to_curve(u[0]) #ELL2
        q1 = cls.map_to_curve(u[1]) #ELL2
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

    @classmethod
    def encode_to_curve_hash2_suite_nu(cls, alpha_string: bytes, salt: bytes = b"",
                                       General_Check: bool = False) -> Self | Any:
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
            tv2 = cls.curve.mod_inverse(tv2)
        except ValueError:
            tv2 = 0

        v = (tv2 * tv1 * s) % field
        w = (tv2 * t * (s - 1)) % field

        # Handle exceptional case
        w = 1 if tv2 == 0 else w

        return cls(v, w)

    @classmethod
    def _x_recover(cls, y: int) -> Tuple[int, int] | int:
        """
        """
        p = cls.curve.PRIME_FIELD
        lhs = (1 - y * y) % p
        rhs = (cls.curve.EdwardsA - cls.curve.EdwardsD * y * y) % p

        try:
            inv_rhs = pow(rhs, -1, p)
        except ValueError:
            return None

        x2 = (lhs * inv_rhs) % p
        x = cls.sqrt_mod(x2)
        if x is None:
            return None

        neg_x = (-x) % p
        # consistent ordering
        return (x, neg_x) if x <= neg_x else (neg_x, x)

    @classmethod
    def sqrt_mod(cls, n: int) -> int | None:
        """Tonelli-Shanks sqrt mod p. Returns r such that r*r % p == n, or None."""
        p = cls.curve.PRIME_FIELD
        n %= p
        if n == 0:
            return 0
        # Legendre symbol
        ls = pow(n, (p - 1) // 2, p)
        if ls == p - 1:
            return None
        if p % 4 == 3:
            return pow(n, (p + 1) // 4, p)

        # Factor p-1 = q * 2^s
        q = p - 1
        s = 0
        while q % 2 == 0:
            q //= 2
            s += 1

        # find a quadratic non-residue z
        z = 2
        while pow(z, (p - 1) // 2, p) != p - 1:
            z += 1

        m = s
        c = pow(z, q, p)
        t = pow(n, q, p)
        r = pow(n, (q + 1) // 2, p)

        while True:
            if t == 0:
                return 0
            if t == 1:
                return r
            # find smallest i (0 < i < m) with t^(2^i) == 1
            i = 1
            t2i = pow(t, 2, p)
            while i < m and t2i != 1:
                t2i = pow(t2i, 2, p)
                i += 1
            if i == m:
                return None
            b = pow(c, 1 << (m - i - 1), p)
            m = i
            c = (b * b) % p
            t = (t * c) % p
            r = (r * b) % p