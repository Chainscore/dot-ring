from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..curve import Curve
from ..specs.parameters import MontgomeryCurveParams


@dataclass(frozen=True, kw_only=True)
class MGCurve(Curve[int]):
    """
    Base class for Montgomery curves of the form: Bv² = u³ + Au² + u

    Standard Montgomery form with:
    - A: coefficient of u² term
    - B: coefficient of v² term (typically 1 for most curves)
    """

    params: MontgomeryCurveParams

    def __post_init__(self) -> None:
        """Validate curve parameters after initialization."""
        super().__post_init__() if hasattr(super(), "__post_init__") else None

        # Validate that B is not zero (would make curve degenerate)
        if self.params.b % self.params.field_modulus == 0:
            raise ValueError("B coefficient cannot be zero mod p")

        # Validate that A² - 4 is not zero (would make curve singular)
        discriminant = (self.params.a * self.params.a - 4) % self.params.field_modulus
        if discriminant == 0:
            raise ValueError("Curve is singular: A² - 4 ≡ 0 (mod p)")

    def is_on_curve(self, point: tuple[int, int]) -> bool:
        """
        Check if point (u, v) satisfies the Montgomery curve equation: Bv² = u³ + Au² + u
        """
        u, v = point
        p = self.params.field_modulus

        # Reduce coordinates modulo p
        u, v = u % p, v % p

        left = (self.params.b * v * v) % p
        right = (u * u * u + self.params.a * u * u + u) % p
        return left == right

    def validate_point(self, point: Any) -> bool:
        """
        Validate that a point is properly constructed and on the curve.
        """
        if hasattr(point, "is_identity") and point.is_identity():
            return True

        if not hasattr(point, "x") or not hasattr(point, "y"):
            return False

        if point.x is None or point.y is None:
            return True  # Identity point

        # Check coordinates are in valid range
        p = self.params.field_modulus
        if not (0 <= point.x < p and 0 <= point.y < p):
            return False

        # Check curve equation
        return self.is_on_curve((point.x, point.y))

    def __eq__(self, other: object) -> bool:
        """Check if two curves are equal."""
        if not isinstance(other, MGCurve):
            return False
        return self.params.field_modulus == other.params.field_modulus and self.params.a == other.params.a and self.params.b == other.params.b

    def __hash__(self) -> int:
        """Hash for use as dictionary keys."""
        return hash((self.params.field_modulus, self.params.a, self.params.b))

    def __str__(self) -> str:
        """String representation of the curve."""
        return f"MGCurve(p={self.params.field_modulus}, A={self.params.a}, B={self.params.b})"

    def __repr__(self) -> str:
        """Detailed string representation."""
        return (
            f"MGCurve(field_modulus={self.params.field_modulus}, A={self.params.a}, B={self.params.b}, "
            f"equation: {self.params.b}*v² = u³ + {self.params.a}*u² + u)"
        )
