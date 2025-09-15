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

    def map_to_curve_sswu(self, u: int) -> Tuple[int, int]:
        """
        Simplified Shallue-van de Woestijne-Ulas (SSWU) map to curve implementation.

        Args:
            u: Field element to map

        Returns:
            Tuple[int, int]: Point on Short Weierstrass curve
        """
        p = self.PRIME_FIELD
        A = self.WeierstrassA
        B = self.WeierstrassB
        Z = self.Z

        # Constants from RFC 9380
        c1 = (p - 3) // 4  # For square root computation
        c2 = Z ** ((p - 1) // 2) % p  # Legendre symbol of Z

        # Try up to 3 different u values if needed
        for u_attempt in [u, u + 1, u + 2]:
            try:
                # Step 1: Compute x1 = (-B/A) * (1 + 1/(u^4 * Z^2 + u^2 * Z))
                tv1 = pow(u_attempt, 2, p)
                tv1 = (tv1 * Z) % p
                tv2 = (tv1 * tv1) % p
                tv2 = (tv2 + tv1) % p
                tv3 = (tv2 + 1) % p
                tv3 = (tv3 * B) % p
                tv4 = self.mod_inverse((tv2 * A) % p, p)
                x1 = (-tv3 * tv4) % p

                # Compute gx1 = x1³ + Ax1 + B
                gx1 = (pow(x1, 3, p) + A * x1 + B) % p

                # Check if gx1 is a square
                if self.is_square(gx1):
                    try:
                        y = self.mod_sqrt(gx1)
                        # Adjust sign
                        if (y & 1) != (u_attempt & 1):
                            y = (-y) % p
                        return (x1, y)
                    except ValueError:
                        # Try x2 if x1 fails
                        pass
                
                # Compute x2 and gx2
                x2 = (c2 * tv1 * x1) % p
                gx2 = (pow(x2, 3, p) + A * x2 + B) % p
                
                try:
                    y = self.mod_sqrt(gx2)
                    # Adjust sign
                    if (y & 1) != (u_attempt & 1):
                        y = (-y) % p
                    return (x2, y)
                except ValueError:
                    # Try next u value
                    continue
                    
            except Exception as e:
                # If any error occurs, try next u value
                continue
        
        # If we get here, all attempts failed
        raise ValueError(f"Failed to map point to curve after multiple attempts (u={u})")

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
