from __future__ import annotations

from dataclasses import dataclass
from typing import Any, cast

from dot_ring.curve.curve import Curve


@dataclass(frozen=True)
class SWCurve(Curve):
    """
    Short Weierstrass Curve implementation.

    A Short Weierstrass curve is defined by the equation:
    y² = x³ + ax + b

    where a, b are elements of the field such that 4a³ + 27b² ≠ 0.

    Attributes:
        WeierstrassA: The 'a' parameter in the curve equation
        WeierstrassB: The 'b' parameter in the curve equation
    """

    WeierstrassA: int | tuple[int, int]
    WeierstrassB: int | tuple[int, int]

    def __post_init__(self) -> None:
        """Validate curve parameters after initialization."""
        super().__post_init__()
        if not self._validate_weierstrass_params():
            raise ValueError("Invalid Short Weierstrass curve parameters")

    def _validate_weierstrass_params(self) -> bool:
        """
        Validate Short Weierstrass specific parameters.

        Handles both Fp and Fp2 curve parameters.

        Returns:
            bool: True if parameters are valid
        """

        def is_fp2(value: Any) -> bool:
            return isinstance(value, (tuple, list)) and len(value) == 2

        A = self.WeierstrassA
        B = self.WeierstrassB
        p = self.PRIME_FIELD

        # Handle Fp2 points
        if is_fp2(A) or is_fp2(B):
            # For Fp2, we'll just check that the parameters are not both zero
            # A more thorough check would involve Fp2 arithmetic
            a_is_zero = (
                all(x == 0 for x in A) if isinstance(A, (tuple, list)) else A == 0
            )
            b_is_zero = (
                all(x == 0 for x in B) if isinstance(B, (tuple, list)) else B == 0
            )
            return not (a_is_zero and b_is_zero)

        # Original Fp validation
        # Check discriminant: 4a³ + 27b² ≠ 0 (mod p)
        a_cubed = pow(cast(int, A), 3, p)
        b_squared = pow(cast(int, B), 2, p)
        discriminant = (4 * a_cubed + 27 * b_squared) % p
        return discriminant != 0

    def is_on_curve(self, point: tuple[Any, Any]) -> bool:
        """
        Check if a given point (x, y) is on the curve.

        Args:
            point: A tuple (x, y) representing the point.

        Returns:
            bool: True if the point is on the curve, False otherwise.
        """
        u, v = cast(int, point[0]), cast(int, point[1])
        # The curve equation is y² = x³ + ax + b
        # We need to check if v² % p == (u³ + a*u + b) % p
        p = self.PRIME_FIELD
        A = cast(int, self.WeierstrassA)
        B = cast(int, self.WeierstrassB)

        left_side = pow(v, 2, p)
        right_side = (pow(u, 3, p) + (A * u) % p + B) % p

        return left_side == right_side

    def j_invariant(self) -> int:
        """
        Calculate the j-invariant of the curve.

        Returns:
            int: j-invariant
        """
        A = self.WeierstrassA
        B = self.WeierstrassB
        p = self.PRIME_FIELD

        discriminant = (4 * pow(cast(int, A), 3, p) + 27 * pow(cast(int, B), 2, p)) % p
        numerator = (1728 * 4 * pow(cast(int, A), 3, p)) % p
        return (numerator * self.mod_inverse(discriminant)) % p
