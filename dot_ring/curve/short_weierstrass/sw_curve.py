from __future__ import annotations

from dataclasses import dataclass
from typing import Generic, TypeVar, cast

from dot_ring.curve.curve import Curve
from dot_ring.curve.fp2 import Fp2
from dot_ring.curve.specs.parameters import ShortWeierstrassCurveParams

CoordT = TypeVar("CoordT", int, Fp2)


@dataclass(frozen=True, kw_only=True)
class SWCurve(Curve[CoordT], Generic[CoordT]):
    """
    Short Weierstrass Curve implementation.

    A Short Weierstrass curve is defined by the equation:
    y² = x³ + ax + b

    where a, b are elements of the field such that 4a³ + 27b² ≠ 0.

    Attributes:
        params: Short Weierstrass curve-suite constants.
    """

    params: ShortWeierstrassCurveParams[CoordT]

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

        A = self.params.a
        B = self.params.b
        p = self.params.field_modulus

        if isinstance(A, Fp2) or isinstance(B, Fp2):
            if not isinstance(A, Fp2) or not isinstance(B, Fp2):
                return False
            discriminant = 4 * (A**3) + 27 * (B**2)
            return not discriminant.is_zero()

        # Original Fp validation
        # Check discriminant: 4a³ + 27b² ≠ 0 (mod p)
        a_cubed = pow(cast(int, A), 3, p)
        b_squared = pow(cast(int, B), 2, p)
        discriminant = (4 * a_cubed + 27 * b_squared) % p
        return discriminant != 0

    def is_on_curve(self, point: tuple[CoordT, CoordT]) -> bool:
        """
        Check if a given point (x, y) is on the curve.

        Args:
            point: A tuple (x, y) representing the point.

        Returns:
            bool: True if the point is on the curve, False otherwise.
        """
        u, v = point
        if isinstance(u, Fp2) or isinstance(v, Fp2):
            return isinstance(u, Fp2) and isinstance(v, Fp2) and v * v == u * u * u + cast(Fp2, self.params.a) * u + cast(Fp2, self.params.b)

        u, v = cast(int, u), cast(int, v)
        p = self.params.field_modulus
        A = cast(int, self.params.a)
        B = cast(int, self.params.b)
        left_side = pow(v, 2, p)
        right_side = (pow(u, 3, p) + (A * u) % p + B) % p

        return left_side == right_side

    def j_invariant(self) -> int:
        """
        Calculate the j-invariant of the curve.

        Returns:
            int: j-invariant
        """
        A = self.params.a
        B = self.params.b
        p = self.params.field_modulus

        discriminant = (4 * pow(cast(int, A), 3, p) + 27 * pow(cast(int, B), 2, p)) % p
        numerator = (1728 * 4 * pow(cast(int, A), 3, p)) % p
        return (numerator * self.mod_inverse(discriminant)) % p
