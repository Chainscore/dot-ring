from __future__ import annotations

from dataclasses import dataclass
from typing import Final, Tuple

# Updated import path to new namespace
from dot_ring.curves.curve import Curve


@dataclass(frozen=True)
class TECurve(Curve):
    """
    Twisted Edwards Curve implementation.

    A Twisted Edwards curve is defined by the equation:
    ax² + y² = 1 + dx²y²

    where a, d are distinct, non-zero elements of the field.
    """

    EdwardsA: Final[int]
    EdwardsD: Final[int]

    # ---- Parameter validation ------------------------------------------------

    def __post_init__(self) -> None:
        super().__post_init__()
        if not self._validate_edwards_params():
            raise ValueError("Invalid Twisted Edwards curve parameters")

    def _validate_edwards_params(self) -> bool:
        return (
            self.EdwardsA != 0
            and self.EdwardsD != 0
            and self.EdwardsA != self.EdwardsD
            and all(x < self.PRIME_FIELD for x in (self.EdwardsA, self.EdwardsD))
        )

    # ---- Elligator-2 helpers --------------------------------------------------

    def calculate_j_k(self) -> Tuple[int, int]:
        p = self.PRIME_FIELD
        denom = (self.EdwardsA - self.EdwardsD) % p
        denom_inv = self.mod_inverse(denom)
        J = (2 * (self.EdwardsA + self.EdwardsD) * denom_inv) % p
        K = (4 * denom_inv) % p
        return J, K

    def map_to_curve_ell2(self, u: int) -> Tuple[int, int]:
        J, K = self.calculate_j_k()
        Z = self.Z
        p = self.PRIME_FIELD
        c1 = (J * self.mod_inverse(K)) % p
        c2 = self.mod_inverse(K * K) % p
        tv1 = (Z * u * u) % p
        e1 = tv1 == -1
        tv1 = 0 if e1 else tv1
        x1 = (-c1 * self.mod_inverse(tv1 + 1)) % p
        gx1 = (((x1 + c1) * x1 + c2) * x1) % p
        x2 = (-x1 - c1) % p
        gx2 = (tv1 * gx1) % p
        e2 = self.is_square(gx1)
        x = x2 if not e2 else x1
        y2 = gx2 if not e2 else gx1
        y = self.mod_sqrt(y2)
        e3 = (y & 1) == 1
        y = -y % p if e2 ^ e3 else y
        s = (x * K) % p
        t = (y * K) % p
        return (s, t)

    # ---- Misc helpers ---------------------------------------------------------

    @property
    def curve_equation(self) -> str:
        return f"{self.EdwardsA}x² + y² = 1 + {self.EdwardsD}x²y²"

    def is_complete(self) -> bool:
        return self.is_square(self.EdwardsA) and not self.is_square(self.EdwardsD)