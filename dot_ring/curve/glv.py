from __future__ import annotations

from dataclasses import dataclass
from typing import List, Tuple, Final
from functools import lru_cache
import math
from .point import CurvePoint


@dataclass(frozen=True)
class GLV:
    """
    Gallant-Lambert-Vanstone endomorphism parameters.

    This class implements the GLV method for faster scalar multiplication
    on elliptic curve that admit an efficient endomorphism.

    Attributes:
        is_enabled: Whether GLV optimization is enabled
        lambda_param: Eigenvalue of the endomorphism
        constant_b: First decomposition constant
        constant_c: Second decomposition constant
    """
    lambda_param: int = 0
    constant_b: int = 0
    constant_c: int = 0

    def __post_init__(self) -> None:
        """Validate GLV parameters."""
        if not self._validate_parameters():
            raise ValueError("Invalid GLV parameters")

    def _validate_parameters(self) -> bool:
        """
        Validate GLV parameters.

        Returns:
            bool: True if parameters are valid
        """
        return self.lambda_param != 0 and self.constant_b != 0 and self.constant_c != 0

    def extended_euclidean_algorithm(
        self, n: int, lam: int
    ) -> List[Tuple[int, int, int]]:
        """
        Compute extended Euclidean algorithm sequence.

        Args:
            n: Curve order
            lam: Lambda parameter

        Returns:
            List[Tuple[int, int, int]]: Sequence of (s, t, r) values
        """
        if n <= 0 or lam <= 0:
            raise ValueError("Inputs must be positive")

        s0, t0, r0 = 1, 0, n
        s1, t1, r1 = 0, 1, lam
        sequence = [(s0, t0, r0), (s1, t1, r1)]

        while r1 != 0:
            q = r0 // r1
            r2 = r0 - q * r1
            s2 = s0 - q * s1
            t2 = t0 - q * t1
            sequence.append((s2, t2, r2))
            s0, t0, r0 = s1, t1, r1
            s1, t1, r1 = s2, t2, r2

        return sequence[:-1]

    @lru_cache(maxsize=None)
    def find_short_vectors(
        self, n: int, lam: int
    ) -> Tuple[Tuple[int, int], Tuple[int, int]]:
        """
        Find short vectors for scalar decomposition.

        Args:
            n: Curve order
            lam: Lambda parameter

        Returns:
            Tuple[Tuple[int, int], Tuple[int, int]]: Two shortest vectors
        """
        sequence = self.extended_euclidean_algorithm(n, lam)
        sqrt_n = math.isqrt(n)

        # Find largest index m where r_m >= sqrt(n)
        m = max(i for i, (_, _, r) in enumerate(sequence) if r >= sqrt_n)

        # Get components for v1
        rm_plus1, tm_plus1 = sequence[m + 1][2], sequence[m + 1][1]
        v1 = (rm_plus1, -tm_plus1)

        # Get components for v2
        if m + 2 < len(sequence):
            rm_plus2, tm_plus2 = sequence[m + 2][2], sequence[m + 2][1]
        else:
            # Use a large integer instead of float("inf") to satisfy type checker
            # Since we are looking for vectors of size ~sqrt(n), n is effectively infinite
            rm_plus2, tm_plus2 = n, n

        v2_candidates = [(sequence[m][2], -sequence[m][1]), (rm_plus2, -tm_plus2)]

        # Choose shorter vector
        v2 = min(v2_candidates, key=lambda v: v[0] ** 2 + v[1] ** 2)

        return v1, v2

    def decompose_scalar(self, k: int, n: int) -> Tuple[int, int]:
        """
        Decompose scalar for faster multiplication.

        Args:
            k: Scalar to decompose
            n: Curve order

        Returns:
            Tuple[int, int]: Decomposed scalar components

        Raises:
            ValueError: If GLV is not enabled
        """
        v1, v2 = self.find_short_vectors(n, self.lambda_param)
        v, b1, b2 = self._find_closest_lattice_point(k, v1, v2, n)

        k1 = (k - v[0]) % n
        k2 = (-v[1]) % n

        return k1, k2

    def _find_closest_lattice_point(
        self, k: int, v1: Tuple[int, int], v2: Tuple[int, int], n: int
    ) -> Tuple[Tuple[int, int], int, int]:
        """
        Find closest lattice point for scalar decomposition.

        Args:
            k: Scalar value
            v1: First basis vector
            v2: Second basis vector
            n: Curve order

        Returns:
            Tuple[Tuple[int, int], int, int]: Lattice point and coefficients
        """
        # Compute beta values using integer arithmetic
        # beta = A_inv @ [k, 0]
        # A_inv = [[v2[1], -v2[0]], [-v1[1], v1[0]]] / det
        # beta1 = k * v2[1] / det
        # beta2 = k * (-v1[1]) / det
        
        det = v1[0] * v2[1] - v1[1] * v2[0]
        
        # Round to nearest integers
        # b = round(num / det) = (num + det//2) // det  (assuming det > 0)
        # If det < 0, we can flip signs of num and det
        
        if det == 0:
            return (0, 0), 0, 0
            
        # b1 = round(k * v2[1] / det)
        num1 = k * v2[1]
        
        # b2 = round(k * (-v1[1]) / det)
        num2 = k * (-v1[1])
        
        # Helper for rounding division
        def round_div(n, d):
            return (n + d // 2) // d
            
        b1 = round_div(num1, det)
        b2 = round_div(num2, det)

        # Compute lattice point
        v = (b1 * v1[0] + b2 * v2[0], b1 * v1[1] + b2 * v2[1])

        return v, b1, b2

    def compute_endomorphism(self, point: CurvePoint) -> CurvePoint:
        """
        Compute the GLV endomorphism of this point.

        Returns:
            CurvePoint: Result of endomorphism
        """
        # These constants should ideally be curve attributes
        B = 0x52C9F28B828426A561F00D3A63511A882EA712770D9AF4D6EE0F014D172510B4
        C = 0x6CC624CF865457C3A97C6EFD6C17D1078456ABCFFF36F4E9515C806CDF650B3D
        x, y, p = point.x, point.y, point.curve.PRIME_FIELD
        y2 = pow(y, 2, p)
        xy = (x * y) % p
        f_y = (C * (1 - y2)) % p
        g_y = (B * (y2 + B)) % p
        h_y = (y2 - B) % p

        x_p = (f_y * h_y) % p
        y_p = (g_y * xy) % p
        z_p = (h_y * xy) % p

        x_a = (x_p * pow(z_p, -1, p)) % p
        y_a = (y_p * pow(z_p, -1, p)) % p

        return point.__class__(x_a, y_a)
    
    def windowed_simultaneous_mult(
        self, k1: int, k2: int, P1: CurvePoint, P2: CurvePoint, w: int = 2
    ) -> CurvePoint:
        """
        Compute k1 * P1 + k2 * P2 using windowed simultaneous multi-scalar multiplication.

        Args:
            k1: First scalar
            k2: Second scalar
            P1: First point
            P2: Second point
            w: Window size (default=2)

        Returns:
            TEAffinePoint: Result of k1*P1 + k2*P2

        Raises:
            TypeError: If P1 or P2 is not compatible with this curve
        """
        from .twisted_edwards.te_projective_point import TEProjectivePoint
        
        if P1.curve != P2.curve:
            raise TypeError("Points must be on the same curve")
        
        P1_proj = TEProjectivePoint.from_point(P1)
        P2_proj = TEProjectivePoint.from_point(P2)
        identity_proj = TEProjectivePoint.zero(P1.curve)

        # Step 1: Precompute lookup table for all i*P1 + j*P2 (0 <= i,j < 2^w)
        table_size = 1 << w
        table = [[None] * table_size for _ in range(table_size)]
        
        # Precompute P1 multiples: [0, P1, 2*P1, 3*P1, ...]
        P1_multiples = [identity_proj]
        current = P1_proj
        for _ in range(1, table_size):
            P1_multiples.append(current)
            current = current + P1_proj
            
        # Precompute P2 multiples: [0, P2, 2*P2, 3*P2, ...]
        P2_multiples = [identity_proj]
        current = P2_proj
        for _ in range(1, table_size):
            P2_multiples.append(current)
            current = current + P2_proj
        
        # Build full table: table[i][j] = i*P1 + j*P2
        for i in range(table_size):
            for j in range(table_size):
                if i == 0:
                    table[i][j] = P2_multiples[j]
                elif j == 0:
                    table[i][j] = P1_multiples[i]
                else:
                    table[i][j] = P1_multiples[i] + P2_multiples[j]

        # Step 2: Split k1 and k2 into w-bit windows
        max_len = max(k1.bit_length(), k2.bit_length())
        d = math.ceil(max_len / w)
        
        # Extract windows directly without intermediate list
        mask = (1 << w) - 1
        
        # Step 3: Double-and-add from MSB to LSB
        R = identity_proj

        for i in range(d - 1, -1, -1):
            # Double w times
            for _ in range(w):
                R = R.double()

            # Extract window indices
            k1_window = (k1 >> (i * w)) & mask
            k2_window = (k2 >> (i * w)) & mask
            
            # Add precomputed value if non-zero
            if k1_window != 0 or k2_window != 0:
                R = R + table[k1_window][k2_window]

        return R.to_affine()
