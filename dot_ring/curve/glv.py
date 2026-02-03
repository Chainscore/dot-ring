from __future__ import annotations

import math
from dataclasses import dataclass
from functools import lru_cache
from typing import Any, TypeVar, cast

from .field_arithmetic import (
    projective_to_affine_cy as projective_to_affine,
)
from .field_arithmetic import (
    scalar_mult_4_cy as _compiled_msm4,
)
from .field_arithmetic import (
    scalar_mult_windowed_cy as _compiled_msm,
)
from .twisted_edwards.te_affine_point import TEAffinePoint

AffinePointT = TypeVar("AffinePointT", bound=TEAffinePoint[Any])


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

    def extended_euclidean_algorithm(self, n: int, lam: int) -> list[tuple[int, int, int]]:
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

    @lru_cache(maxsize=1024)  # noqa: B019
    def find_short_vectors(self, n: int, lam: int) -> tuple[tuple[int, int], tuple[int, int]]:
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

    def decompose_scalar(self, k: int, n: int) -> tuple[int, int]:
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

        v1_0, v1_1 = v1
        v2_0, v2_1 = v2

        det = v1_0 * v2_1 - v1_1 * v2_0

        num1 = k * v2_1
        b1 = (num1 + det // 2) // det

        num2 = k * -v1_1
        b2 = (num2 + det // 2) // det

        vx = b1 * v1_0 + b2 * v2_0
        vy = b1 * v1_1 + b2 * v2_1

        k1 = k - vx
        k2 = -vy

        return k1, k2

    @lru_cache(maxsize=128)  # noqa: B019
    def compute_endomorphism(self, point: AffinePointT) -> AffinePointT:
        """
        Compute the GLV endomorphism of this point.

        Returns:
            AffinePointT: Result of endomorphism
        """
        x, y, p = point.x, point.y, point.curve.PRIME_FIELD

        # These constants should ideally be curve attributes
        B = 0x52C9F28B828426A561F00D3A63511A882EA712770D9AF4D6EE0F014D172510B4
        C = 0x6CC624CF865457C3A97C6EFD6C17D1078456ABCFFF36F4E9515C806CDF650B3D
        if x is None or y is None:
            return point.__class__(None, None)
        y2 = pow(cast(int, y), 2, p)
        xy = (cast(int, x) * cast(int, y)) % p
        f_y = (C * (1 - y2)) % p
        g_y = (B * (y2 + B)) % p
        h_y = (y2 - B) % p

        x_p = (f_y * h_y) % p
        y_p = (g_y * xy) % p
        z_p = (h_y * xy) % p

        x_a = (x_p * pow(z_p, -1, p)) % p
        y_a = (y_p * pow(z_p, -1, p)) % p

        return point.__class__(x_a, y_a)

    def windowed_simultaneous_mult(self, k1: int, k2: int, P1: AffinePointT, P2: AffinePointT, w: int = 2) -> AffinePointT:
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
        if P1.curve != P2.curve:
            raise TypeError("Points must be on the same curve")

        # Handle negative scalars
        if k1 < 0:
            k1 = -k1
            P1 = -P1
        if k2 < 0:
            k2 = -k2
            P2 = -P2

        p = P1.curve.PRIME_FIELD
        a_coeff = P1.curve.EdwardsA
        d_coeff = P1.curve.EdwardsD

        # Convert to projective coordinates
        if P1.x is None or P1.y is None or P2.x is None or P2.y is None:
            # Handle identity points
            if P1.is_identity():
                return P2 * k2
            if P2.is_identity():
                return P1 * k1
            raise ValueError("Invalid points")

        p1_t = P1.x * P1.y % p
        p2_t = P2.x * P2.y % p

        assert projective_to_affine is not None
        # Use compiled MSM
        rx, ry, rz, rt = _compiled_msm(k1, k2, P1.x, P1.y, 1, p1_t, P2.x, P2.y, 1, p2_t, a_coeff, d_coeff, p, w)

        # Convert back to affine
        ax, ay = projective_to_affine(rx, ry, rz, p)
        point_cls = cast(type[AffinePointT], P1.__class__)
        return point_cls(ax, ay)

    def multi_scalar_mult_4(
        self,
        k1: int,
        k2: int,
        k3: int,
        k4: int,
        P1: AffinePointT,
        P2: AffinePointT,
        P3: AffinePointT,
        P4: AffinePointT,
        w: int = 2,
    ) -> AffinePointT:
        """
        Compute k1*P1 + k2*P2 + k3*P3 + k4*P4 using windowed simultaneous multi-scalar multiplication.

        This is faster than doing 4 separate scalar multiplications.

        Args:
            k1, k2, k3, k4: Scalars
            P1, P2, P3, P4: Points
            w: Window size (default=2)

        Returns:
            TEAffinePoint: Result of k1*P1 + k2*P2 + k3*P3 + k4*P4
        """
        # Handle negative scalars
        if k1 < 0:
            k1 = -k1
            P1 = -P1
        if k2 < 0:
            k2 = -k2
            P2 = -P2
        if k3 < 0:
            k3 = -k3
            P3 = -P3
        if k4 < 0:
            k4 = -k4
            P4 = -P4

        p = P1.curve.PRIME_FIELD
        a_coeff = P1.curve.EdwardsA
        d_coeff = P1.curve.EdwardsD

        # Convert to projective coordinates
        if P1.x is None or P1.y is None or P2.x is None or P2.y is None or P3.x is None or P3.y is None or P4.x is None or P4.y is None:
            # Fallback to simple addition for identity points
            res = P1 * k1 + P2 * k2  # type: ignore[operator]
            res = res + P3 * k3  # type: ignore[operator]
            res = res + P4 * k4  # type: ignore[operator]
            return res

        p1_t = (cast(int, P1.x) * cast(int, P1.y)) % p
        p2_t = (cast(int, P2.x) * cast(int, P2.y)) % p
        p3_t = (cast(int, P3.x) * cast(int, P3.y)) % p
        p4_t = (cast(int, P4.x) * cast(int, P4.y)) % p

        assert projective_to_affine is not None
        rx, ry, rz, rt = _compiled_msm4(
            k1,
            k2,
            k3,
            k4,
            P1.x,
            P1.y,
            1,
            p1_t,
            P2.x,
            P2.y,
            1,
            p2_t,
            P3.x,
            P3.y,
            1,
            p3_t,
            P4.x,
            P4.y,
            1,
            p4_t,
            a_coeff,
            d_coeff,
            p,
            w,
        )

        ax, ay = projective_to_affine(rx, ry, rz, p)
        point_cls = cast(type[AffinePointT], P1.__class__)
        return point_cls(ax, ay)
