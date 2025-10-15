"""
Field element implementation for finite field arithmetic.

This module provides a FieldElement class that implements arithmetic operations
in finite fields, particularly useful for cryptographic operations.
"""

from __future__ import annotations

from typing import Union, Optional


class FieldElement:
    """
    Represents an element in a finite field Fp or its quadratic extension Fp2.

    For Fp elements, set im=0.
    For Fp2 elements, use (re, im) where the element is re + im * I (I = sqrt(-1)).
    """

    def __init__(self, re: int, im: int, p: int):
        """
        Initialize a field element.

        Args:
            re: Real part of the element
            im: Imaginary part of the element (0 for Fp)
            p: Prime modulus of the field
        """
        self.re = re % p
        self.im = im % p
        self.p = p

    def __add__(self, other: Union[FieldElement, int]) -> FieldElement:
        """Add two field elements or a field element and an integer."""
        if isinstance(other, FieldElement):
            if self.p != other.p:
                raise ValueError("Cannot add elements from different fields")
            return FieldElement(
                (self.re + other.re) % self.p,
                (self.im + other.im) % self.p,
                self.p
            )
        return FieldElement(
            (self.re + other) % self.p,
            self.im,
            self.p
        )

    # def __sub__(self, other: Union[FieldElement, int]) -> FieldElement:
    #     """Subtract two field elements or a field element and an integer."""
    #     if isinstance(other, FieldElement):
    #         if self.p != other.p:
    #             raise ValueError("Cannot subtract elements from different fields")
    #         return FieldElement(
    #             (self.re - other.re) % self.p,
    #             (self.im - other.im) % self.p,
    #             self.p
    #         )
    #     return FieldElement(
    #         (self.re - other) % self.p,
    #         self.im,
    #         self.p
    #     )

    def __mul__(self, other: Union[FieldElement, int]) -> FieldElement:
        """Multiply two field elements or a field element and an integer."""
        if isinstance(other, FieldElement):
            if self.p != other.p:
                raise ValueError("Cannot multiply elements from different fields")
            # (a + bi)(c + di) = (ac - bd) + (ad + bc)i
            re = (self.re * other.re - self.im * other.im) % self.p
            im = (self.re * other.im + self.im * other.re) % self.p
            return FieldElement(re, im, self.p)
        return FieldElement(
            (self.re * other) % self.p,
            (self.im * other) % self.p,
            self.p
        )

    def __truediv__(self, other: Union[FieldElement, int]) -> FieldElement:
        """Divide two field elements or a field element by an integer."""
        if isinstance(other, FieldElement):
            return self * other.inv()
        inv_other = pow(other, -1, self.p)
        return self * inv_other

    def inv(self) -> FieldElement:
        """Compute the multiplicative inverse using Fermat's Little Theorem."""
        # For Fp2, the inverse of (a + bi) is (a - bi)/(a² + b²)
        denom = (self.re * self.re + self.im * self.im) % self.p
        inv_denom = pow(denom, -1, self.p)
        return FieldElement(
            (self.re * inv_denom) % self.p,
            (-self.im * inv_denom) % self.p,
            self.p
        )

    def __neg__(self) -> FieldElement:
        """Negate the field element."""
        return FieldElement(-self.re % self.p, -self.im % self.p, self.p)

    def __eq__(self, other: object) -> bool:
        """Check if two field elements are equal."""
        if not isinstance(other, (FieldElement, int)):
            return NotImplemented
        if isinstance(other, FieldElement):
            return self.re == other.re and self.im == other.im and self.p == other.p
        return self.im == 0 and self.re == other % self.p

    def is_zero(self) -> bool:
        """Check if the field element is zero."""
        return self.re == 0 and self.im == 0

    def is_square(self) -> bool:
        """Check if the element is a square in the field."""
        if self.im == 0:
            return pow(self.re, (self.p - 1) // 2, self.p) == 1
        # For Fp2, check if norm is a square in Fp
        norm = (self.re * self.re + self.im * self.im) % self.p
        return pow(norm, (self.p - 1) // 2, self.p) == 1


    # def __repr__(self) -> str:
    #     """Canonical string representation of the field element."""
    #     return f"FieldElement({self.re}, {self.im}, {self.p})"

    def __radd__(self, other: int) -> FieldElement:
        """Handle integer addition from the left."""
        return self + other

    # def __rtruediv__(self, other: int) -> FieldElement:
    #     """Handle integer division from the left."""
    #     return FieldElement(other, 0, self.p) / self

    def __pow__(self, exponent: int) -> FieldElement:
        """Raise the field element to an integer power."""
        if not isinstance(exponent, int):
            raise TypeError("Exponent must be an integer")
        if exponent < 0:
            return self.inv() ** (-exponent)
        result = FieldElement(1, 0, self.p)
        base = self
        while exponent > 0:
            if exponent % 2 == 1:
                result = result * base
            base = base * base
            exponent = exponent // 2
        return result

    def sqrt(self) -> Optional[FieldElement]:
        if self.im == 0:
            # Fp case (Tonelli-Shanks, unchanged)
            a = self.re
            if pow(a, (self.p - 1) // 2, self.p) != 1:
                return None  # Not a square

            # Tonelli-Shanks
            Q = self.p - 1
            S = 0
            while Q % 2 == 0:
                Q //= 2
                S += 1
            z = 2
            while pow(z, (self.p - 1) // 2, self.p) != self.p - 1:
                z += 1

            c = pow(z, Q, self.p)
            x = pow(a, (Q + 1) // 2, self.p)
            t = pow(a, Q, self.p)
            m = S

            while t != 1:
                i, temp = 0, t
                while temp != 1 and i < m:
                    temp = (temp * temp) % self.p
                    i += 1
                if i == m:
                    return None
                b = pow(c, 1 << (m - i - 1), self.p)
                x = (x * b) % self.p
                t = (t * b * b) % self.p
                c = (b * b) % self.p
                m = i
            return FieldElement(x, 0, self.p)

        # --- Fp2 case (fixed) ---
        a0, a1 = self.re, self.im
        p = self.p

        if a0 == 0 and a1 == 0:
            return FieldElement(0, 0, p)

        # Step 1: α = a0² + a1²
        alpha = (a0 * a0 + a1 * a1) % p

        # Step 2: sqrt_alpha = sqrt(α) in Fp
        sqrt_alpha = FieldElement(alpha, 0, p).sqrt()
        if sqrt_alpha is None:
            return None

        inv2 = pow(2, -1, p)

        # Step 3: compute candidate x0 = (a0 + sqrt_alpha)/2
        x0 = ((a0 + sqrt_alpha.re) * inv2) % p
        x1 = ((a0 - sqrt_alpha.re) * inv2) % p

        # Step 4: pick the candidate that is a square in Fp
        if pow(x0, (p - 1) // 2, p) == 1:
            y = FieldElement(x0, 0, p).sqrt()
        elif pow(x1, (p - 1) // 2, p) == 1:
            y = FieldElement(x1, 0, p).sqrt()
        else:
            return None  # No square root exists

        # Step 5: compute imaginary part: x = a1 / (2*y)
        inv_2y = pow(2 * y.re, -1, p)
        x = (a1 * inv_2y) % p
        return FieldElement(y.re, x, p)



