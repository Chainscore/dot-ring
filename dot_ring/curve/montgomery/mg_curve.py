from __future__ import annotations
from dataclasses import dataclass
from typing import Final, Tuple
from ..curve import Curve


@dataclass(frozen=True)
class MGCurve(Curve):
    """
    Base class for Montgomery curves of the form: Bv² = u³ + Au² + u

    Standard Montgomery form with:
    - A: coefficient of u² term
    - B: coefficient of v² term (typically 1 for most curves)
    """

    A: Final[int]
    B: Final[int]

    def is_on_curve(self, point: Tuple[int, int]) -> bool:
        """
        Check if point (u, v) satisfies the Montgomery curve equation: Bv² = u³ + Au² + u
        """
        u, v = point
        p = self.PRIME_FIELD

        # Reduce coordinates modulo p
        u, v = u % p, v % p

        left = (self.B * v * v) % p
        right = (u * u * u + self.A * u * u + u) % p
        return left == right
