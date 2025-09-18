from __future__ import annotations

from abc import abstractmethod
from dataclasses import dataclass
from typing import Final, Tuple
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

        Returns:
            bool: True if parameters are valid
        """
        # Check discriminant: 4a³ + 27b² ≠ 0 (mod p)
        discriminant = (4 * pow(self.WeierstrassA, 3, self.PRIME_FIELD) + 
                       27 * pow(self.WeierstrassB, 2, self.PRIME_FIELD)) % self.PRIME_FIELD
        return discriminant != 0


    def j_invariant(self) -> int:
        """
        Calculate the j-invariant of the curve.

        Returns:
            int: j-invariant
        """
        A = self.WeierstrassA
        B = self.WeierstrassB
        p = self.PRIME_FIELD
        
        discriminant = (4 * pow(A, 3, p) + 27 * pow(B, 2, p)) % p
        numerator = (1728 * 4 * pow(A, 3, p)) % p
        return (numerator * self.mod_inverse(discriminant)) % p
