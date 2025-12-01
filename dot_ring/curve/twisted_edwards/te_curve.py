from __future__ import annotations

from dataclasses import dataclass

from dot_ring.curve.curve import Curve
from dot_ring.curve.fast_math import map_to_curve_ell2_fast


@dataclass(frozen=True)
class TECurve(Curve):
    """
    Twisted Edwards Curve implementation.

    A Twisted Edwards curve is defined by the equation:
    ax² + y² = 1 + dx²y²

    where a, d are distinct, non-zero elements of the field.

    Attributes:
        EdwardsA: The 'a' parameter in the curve equation
        EdwardsD: The 'd' parameter in the curve equation
        CHALLENGE_LENGTH: Length of the challenge in bytes (default: 32 for 256-bit security)
    """

    EdwardsA: int
    EdwardsD: int

    def __post_init__(self) -> None:
        """Validate curve parameters after initialization."""
        super().__post_init__()
        if not self._validate_edwards_params():
            raise ValueError("Invalid Twisted Edwards curve parameters")

    def _validate_edwards_params(self) -> bool:
        """
        Validate Twisted Edwards specific parameters.

        Returns:
            bool: True if parameters are valid
        """
        return (
            self.EdwardsA != 0
            and self.EdwardsD != 0
            and self.EdwardsA != self.EdwardsD
            and all(x < self.PRIME_FIELD for x in (self.EdwardsA, self.EdwardsD))
        )

    # @lru_cache(maxsize=1024)  # noqa: B019
    def calculate_j_k(self) -> tuple[int, int]:
        """
        Calculate curve parameters J and K for Elligator 2.

        Returns:
            Tuple[int, int]: J and K parameters
        """
        p = self.PRIME_FIELD
        denom = (self.EdwardsA - self.EdwardsD) % p
        denom_inv = self.mod_inverse(denom)

        J = (2 * (self.EdwardsA + self.EdwardsD) * denom_inv) % p
        K = (4 * denom_inv) % p

        return J, K

    def map_to_curve_ell2(self, u: int) -> tuple[int, int]:
        """
        Elligator 2 map to curve implementation.

        Args:
            u: Field element to map

        Returns:
            Point: Point on Montgomery curve
        """
        J, K = self.calculate_j_k()
        Z = self.Z
        p = self.PRIME_FIELD

        from typing import cast

        return cast(tuple[int, int], map_to_curve_ell2_fast(u, J, K, Z, p))

    @property
    def curve_equation(self) -> str:
        """
        Get the curve equation in readable form.

        Returns:
            str: Curve equation
        """
        return f"{self.EdwardsA}x² + y² = 1 + {self.EdwardsD}x²y²"

    def is_complete(self) -> bool:
        """
        Check if the curve is complete.

        A Twisted Edwards curve is complete if:
        - a is square
        - d is non-square
        in the base field.

        Returns:
            bool: True if curve is complete
        """
        return self.is_square(self.EdwardsA) and not self.is_square(self.EdwardsD)
