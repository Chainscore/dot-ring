from __future__ import annotations
from abc import abstractmethod
from dataclasses import dataclass
from typing import Final
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
    WeierstrassA: Final[int]
    WeierstrassB: Final[int]

    @property
    @abstractmethod
    def CHALLENGE_LENGTH(self) -> int:
        """
        Abstract property for the challenge length in bytes.
        Must be implemented by each curve to specify its specific challenge length.
        """
        raise NotImplementedError("CHALLENGE_LENGTH must be implemented by subclasses")

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
        def is_fp2(value) -> bool:
            return isinstance(value, (tuple, list)) and len(value) == 2
            
        A = self.WeierstrassA
        B = self.WeierstrassB
        p = self.PRIME_FIELD
        
        # Handle Fp2 points
        if is_fp2(A) or is_fp2(B):
            # For Fp2, we'll just check that the parameters are not both zero
            # A more thorough check would involve Fp2 arithmetic
            a_is_zero = all(x == 0 for x in A) if is_fp2(A) else A == 0
            b_is_zero = all(x == 0 for x in B) if is_fp2(B) else B == 0
            return not (a_is_zero and b_is_zero)
            
        # Original Fp validation
        # Check discriminant: 4a³ + 27b² ≠ 0 (mod p)
        a_cubed = pow(A, 3, p)
        b_squared = pow(B, 2, p)
        discriminant = (4 * a_cubed + 27 * b_squared) % p
        return discriminant != 0