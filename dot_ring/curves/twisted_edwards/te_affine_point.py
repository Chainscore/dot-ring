# ruff: noqa
# mypy: ignore-errors

from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass
# pyright: reportGeneralTypeIssues=false
from typing import Self

from sympy import mod_inverse  # type: ignore

from dot_ring.curves.e2c import E2C_Variant
from dot_ring.curves.point import Point, PointProtocol

from .te_curve import TECurve


class TEAffinePoint(Point[TECurve]):
    """Twisted Edwards affine point implementation (migrated)."""

    # ---------------------------------------------------------------------
    # Validation helpers
    # ---------------------------------------------------------------------

    def __post_init__(self) -> None:
        super().__post_init__()
        if not isinstance(self.curve, TECurve):
            raise TypeError("Curve must be a Twisted Edwards curve")

    def is_on_curve(self) -> bool:  # noqa: D401
        v, w = self.x, self.y
        p = self.curve.PRIME_FIELD
        lhs = (self.curve.EdwardsA * pow(v, 2, p) + pow(w, 2, p)) % p
        rhs = (1 + self.curve.EdwardsD * pow(v, 2, p) * pow(w, 2, p)) % p
        return lhs == rhs

    # ---------------------------------------------------------------------
    # Basic group operations (+, -, doubling, scalar-mul)
    # ---------------------------------------------------------------------

    def __add__(self, other, /) -> "TEAffinePoint":  # type: ignore[override,return-value]
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
        x1y2 = (x1 * y2) % p
        x2y1 = (x2 * y1) % p
        y1y2 = (y1 * y2) % p
        x1x2 = (x1 * x2) % p
        dx1x2y1y2 = (self.curve.EdwardsD * x1x2 * y1y2) % p
        x3 = ((x1y2 + x2y1) * self.curve.mod_inverse(1 + dx1x2y1y2)) % p
        y3 = ((y1y2 - self.curve.EdwardsA * x1x2) * self.curve.mod_inverse(1 - dx1x2y1y2)) % p
        return self.__class__(x3, y3)  # type: ignore[arg-type]

    def __neg__(self) -> "TEAffinePoint":  # type: ignore[override]
        return self.__class__(-self.x % self.curve.PRIME_FIELD, self.y)  # type: ignore[arg-type]

    def __sub__(self, other, /) -> "TEAffinePoint":  # type: ignore[override,return-value]
        return self + (-other)  # type: ignore[arg-type]

    def double(self) -> Self:  # noqa: A003
        x1, y1 = self.x, self.y
        p = self.curve.PRIME_FIELD
        if y1 == 0:
            return self.identity_point()
        denom_x = (self.curve.EdwardsA * x1 ** 2 + y1 ** 2) % p
        denom_y = (2 - self.curve.EdwardsA * x1 ** 2 - y1 ** 2) % p
        if denom_x == 0 or denom_y == 0:
            return self.identity_point()
        x3 = (2 * x1 * y1 * self.curve.mod_inverse(denom_x)) % p
        y3 = ((y1 ** 2 - self.curve.EdwardsA * x1 ** 2) * self.curve.mod_inverse(denom_y)) % p
        return self.__class__(x3, y3)  # type: ignore[arg-type]

    # ---- Scalar multiplication ------------------------------------------------

    def __mul__(self, scalar: int) -> Self:  # type: ignore[override]
        if self.curve.glv.is_enabled:
            return self.glv_mul(scalar)
        return self.scalar_mul(scalar)

    def scalar_mul(self, scalar: int) -> "TEAffinePoint":  # type: ignore[return-value]
        result = self.identity_point()
        addend = self
        scalar = scalar % self.curve.ORDER
        while scalar:
            if scalar & 1:
                result = result + addend  # type: ignore[operator]
            addend = addend.double()
            scalar >>= 1
        return result

    def glv_mul(self, scalar: int) -> "TEAffinePoint":  # type: ignore[return-value]
        n = self.curve.ORDER
        k1, k2 = self.curve.glv.decompose_scalar(scalar % n, n)
        phi = self.compute_endomorphism()
        return self.windowed_simultaneous_mult(k1, k2, self, phi, w=2)

    def windowed_simultaneous_mult(
        self,
        k1: int,
        k2: int,
        P1,
        P2,
        w: int = 2,
    ) -> "TEAffinePoint":  # type: ignore[return-value]
        if not isinstance(P1, TEAffinePoint) or not isinstance(P2, TEAffinePoint):
            raise TypeError("Points must be TEAffinePoints")
        if P1.curve != self.curve or P2.curve != self.curve:
            raise ValueError("Points must be on the same curve")

        def split_scalar(scalar: int, width: int, chunks: int) -> list[int]:
            mask = (1 << width) - 1
            return [(scalar >> (i * width)) & mask for i in range(chunks)]

        table = {}
        identity = self.identity_point()

        for i in range(1 << w):
            Pi = P1.scalar_mul(i) if i != 0 else identity
            for j in range(1 << w):
                Qj = P2.scalar_mul(j) if j != 0 else identity
                table[(i, j)] = Pi + Qj  # type: ignore[operator]

        max_len = max(k1.bit_length(), k2.bit_length())
        d = math.ceil(max_len / w)
        k1_windows = split_scalar(k1, w, d)
        k2_windows = split_scalar(k2, w, d)
        R = identity
        for i in range(d - 1, -1, -1):
            for _ in range(w):
                R = R.double()
            idx = (k1_windows[i], k2_windows[i])
            if idx in table:
                R = R + table[idx]  # type: ignore[operator]
        return R

    # ---- Endomorphism ---------------------------------------------------------

    def compute_endomorphism(self) -> Self:
        p = self.curve.PRIME_FIELD
        B = 0x52C9F28B828426A561F00D3A63511A882EA712770D9AF4D6EE0F014D172510B4
        C = 0x6CC624CF865457C3A97C6EFD6C17D1078456ABCFFF36F4E9515C806CDF650B3D
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
        return self.__class__(x_a, y_a)  # type: ignore[arg-type]

    # ---------------------------------------------------------------------
    # Cofactor clearing, encoding, etc.
    # ---------------------------------------------------------------------

    def identity_point(self) -> "TEAffinePoint":  # type: ignore[return-value]
        return self.__class__(0, 1)  # type: ignore[arg-type]

    def clear_cofactor(self) -> "TEAffinePoint":  # type: ignore[return-value]
        return self * self.curve.COFACTOR

    # -- Encode-to-curve --------------------------------------------------------

    @classmethod
    def encode_to_curve(cls, alpha_string: bytes | str, *, salt: bytes | str = b"") -> Self:  # noqa: D401,E501
        if not isinstance(alpha_string, bytes):
            alpha_string = bytes.fromhex(alpha_string)  # type: ignore[arg-type]
        if not isinstance(salt, bytes):
            salt = bytes.fromhex(salt)  # type: ignore[arg-type]
        if cls.curve.E2C == E2C_Variant.ELL2:
            return cls.encode_to_curve_hash2_suite(alpha_string, salt)
        if cls.curve.E2C == E2C_Variant.TAI:
            return cls.encode_to_curve_tai(alpha_string, salt)
        raise ValueError("Unexpected E2C Variant")

    @classmethod
    def encode_to_curve_hash2_suite(cls, alpha_string: bytes, salt: bytes = b"") -> Self:
        string_to_hash = salt + alpha_string
        u = cls.curve.hash_to_field(string_to_hash, 2)
        q0 = cls.map_to_curve(u[0])
        q1 = cls.map_to_curve(u[1])
        return (q0 + q1).clear_cofactor()  # type: ignore[operator]

    @classmethod
    def encode_to_curve_tai(cls, alpha_string: bytes, salt: bytes = b"") -> Self:
        ctr = 0
        H: "TEAffinePoint | str" = "INVALID"
        front = b"\x01"
        back = b"\x00"
        salt = salt.encode() if isinstance(salt, str) else salt
        suite_string = b""  # TODO: set suite string later
        while H == "INVALID" or H == (0, 1):
            ctr_string = ctr.to_bytes(1, "big")
            hash_input = suite_string + front + b"" + alpha_string + ctr_string + back
            hash_output = hashlib.sha256(hash_input).digest()
            H = cls.string_to_point(b"0x02" + hash_output)  # type: ignore[arg-type]
            if H != "INVALID" and cls.curve.COFACTOR > 1:  # type: ignore[operator]
                H = H.scalar_mul(cls.curve.COFACTOR)  # type: ignore[attr-defined]
            ctr += 1
        return H  # type: ignore[return-value]

    @classmethod
    def map_to_curve(cls, u: int) -> Self:
        s, t = cls.curve.map_to_curve_ell2(u)
        return cls.from_mont(s, t)

    @classmethod
    def from_mont(cls, s: int, t: int) -> Self:
        field = cls.curve.PRIME_FIELD
        tv1 = (s + 1) % field
        tv2 = (tv1 * t) % field
        try:
            tv2 = cls.curve.mod_inverse(tv2)
        except ValueError:
            tv2 = 0
        v = (tv2 * tv1 * s) % field
        w = (tv2 * t * (s - 1)) % field
        w = 1 if tv2 == 0 else w
        return cls(v, w)  # type: ignore[arg-type]

    @classmethod
    def _x_recover(cls, y: int) -> int:  # noqa: D401
        lhs = 1 - (y ** 2) % cls.curve.PRIME_FIELD
        rhs = cls.curve.EdwardsA - (cls.curve.EdwardsD * (y ** 2)) % cls.curve.PRIME_FIELD
        val = cls.curve.mod_inverse(rhs)
        do_sqrt = lhs * val % cls.curve.PRIME_FIELD
        return cls.curve.mod_sqrt(do_sqrt) % cls.curve.PRIME_FIELD