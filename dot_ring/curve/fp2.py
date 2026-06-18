from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Self


def _sqrt_fp(value: int, p: int) -> int | None:
    value %= p
    if value == 0:
        return 0
    if pow(value, (p - 1) // 2, p) != 1:
        return None
    if p % 4 == 3:
        return pow(value, (p + 1) // 4, p)

    q = p - 1
    s = 0
    while q % 2 == 0:
        q //= 2
        s += 1

    z = 2
    while pow(z, (p - 1) // 2, p) != p - 1:
        z += 1

    m = s
    c = pow(z, q, p)
    t = pow(value, q, p)
    r = pow(value, (q + 1) // 2, p)
    while t != 1:
        i = 1
        t2i = (t * t) % p
        while i < m and t2i != 1:
            t2i = (t2i * t2i) % p
            i += 1
        if i == m:
            return None
        b = pow(c, 1 << (m - i - 1), p)
        m = i
        c = (b * b) % p
        t = (t * c) % p
        r = (r * b) % p
    return r


def _is_square_fp(value: int, p: int) -> bool:
    value %= p
    return value == 0 or pow(value, (p - 1) // 2, p) == 1


@dataclass(frozen=True, slots=True)
class Fp2:
    """Element of Fp2 represented as `re + im * i`, where `i^2 = -1`."""

    re: int
    im: int
    p: int

    def __post_init__(self) -> None:
        if self.p <= 2:
            raise ValueError("Fp2 modulus must be an odd prime")
        object.__setattr__(self, "re", self.re % self.p)
        object.__setattr__(self, "im", self.im % self.p)

    def _coerce(self, other: Fp2 | int) -> Fp2:
        if isinstance(other, int):
            return Fp2(other, 0, self.p)
        if isinstance(other, Fp2):
            if self.p != other.p:
                raise ValueError("Cannot mix Fp2 elements from different fields")
            return other
        return NotImplemented

    def __add__(self, other: Fp2 | int) -> Fp2:
        rhs = self._coerce(other)
        return Fp2(self.re + rhs.re, self.im + rhs.im, self.p)

    def __radd__(self, other: int) -> Fp2:
        return self + other

    def __sub__(self, other: Fp2 | int) -> Fp2:
        rhs = self._coerce(other)
        return Fp2(self.re - rhs.re, self.im - rhs.im, self.p)

    def __rsub__(self, other: int) -> Fp2:
        return Fp2(other, 0, self.p) - self

    def __mul__(self, other: Fp2 | int) -> Fp2:
        rhs = self._coerce(other)
        return Fp2(
            self.re * rhs.re - self.im * rhs.im,
            self.re * rhs.im + self.im * rhs.re,
            self.p,
        )

    def __rmul__(self, other: int) -> Fp2:
        return self * other

    def __truediv__(self, other: Fp2 | int) -> Fp2:
        return self * self._coerce(other).inv()

    def __neg__(self) -> Fp2:
        return Fp2(-self.re, -self.im, self.p)

    def __pow__(self, exponent: int) -> Fp2:
        if not isinstance(exponent, int):
            raise TypeError("Exponent must be an integer")
        if exponent < 0:
            return self.inv() ** (-exponent)
        result = Fp2(1, 0, self.p)
        base = self
        while exponent:
            if exponent & 1:
                result *= base
            base *= base
            exponent >>= 1
        return result

    def __eq__(self, other: object) -> bool:
        if isinstance(other, int):
            return self.im == 0 and self.re == other % self.p
        if not isinstance(other, Fp2):
            return NotImplemented
        return self.re == other.re and self.im == other.im and self.p == other.p

    def inv(self) -> Fp2:
        if self.is_zero():
            raise ZeroDivisionError("Cannot invert zero in Fp2")
        denom = (self.re * self.re + self.im * self.im) % self.p
        inv_denom = pow(denom, -1, self.p)
        return Fp2(self.re * inv_denom, -self.im * inv_denom, self.p)

    def is_zero(self) -> bool:
        return self.re == 0 and self.im == 0

    def norm(self) -> int:
        return (self.re * self.re + self.im * self.im) % self.p

    def is_square(self) -> bool:
        return self.is_zero() or _is_square_fp(self.norm(), self.p)

    def sqrt(self) -> Fp2 | None:
        if self.is_zero():
            return Fp2(0, 0, self.p)

        if self.im == 0:
            root = _sqrt_fp(self.re, self.p)
            if root is not None:
                return Fp2(root, 0, self.p)
            imaginary_root = _sqrt_fp(-self.re, self.p)
            if imaginary_root is not None:
                return Fp2(0, imaginary_root, self.p)
            return None

        sqrt_norm = _sqrt_fp(self.norm(), self.p)
        if sqrt_norm is None:
            return None

        inv2 = pow(2, -1, self.p)
        for candidate in ((self.re + sqrt_norm) * inv2, (self.re - sqrt_norm) * inv2):
            candidate %= self.p
            if not _is_square_fp(candidate, self.p):
                continue
            real = _sqrt_fp(candidate, self.p)
            if real is None or real == 0:
                continue
            imag = (self.im * pow(2 * real, -1, self.p)) % self.p
            root = Fp2(real, imag, self.p)
            if root * root == self:
                return root
        return None

    def sgn0(self) -> int:
        return self.re % 2 if self.re != 0 else self.im % 2

    def to_tuple(self) -> tuple[int, int]:
        return self.re, self.im

    def to_fq2(self) -> Any:
        from py_ecc.bls12_381 import FQ2

        return FQ2([self.re, self.im])

    @classmethod
    def from_fq2(cls, value: Any, p: int) -> Self:
        return cls(int(value.coeffs[0]), int(value.coeffs[1]), p)
