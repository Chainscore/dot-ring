from __future__ import annotations

from dataclasses import dataclass
from typing import List, Tuple, Final, TYPE_CHECKING

import numpy as np  # type: ignore
from sympy import sqrt  # type: ignore


@dataclass(frozen=True)
class GLVSpecs:
    """
    Gallant-Lambert-Vanstone endomorphism parameters.

    Identical to the legacy implementation but namespaced under
    ``dot_ring.curves``.
    """

    is_enabled: Final[bool] = False
    lambda_param: Final[int] = 0
    constant_b: Final[int] = 0
    constant_c: Final[int] = 0

    # ... rest of the implementation copied verbatim ...

    def __post_init__(self) -> None:
        if self.is_enabled and not self._validate_parameters():
            raise ValueError("Invalid GLV parameters")

    def _validate_parameters(self) -> bool:
        return (
            self.lambda_param != 0
            and self.constant_b != 0
            and self.constant_c != 0
        )

    def extended_euclidean_algorithm(self, n: int, lam: int) -> List[Tuple[int, int, int]]:
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

    def find_short_vectors(self, n: int, lam: int) -> Tuple[Tuple[int, int], Tuple[int, int]]:
        sequence = self.extended_euclidean_algorithm(n, lam)
        sqrt_n = int(sqrt(n))

        m = max(i for i, (_, _, r) in enumerate(sequence) if r >= sqrt_n)

        rm_plus1, tm_plus1 = sequence[m + 1][2], sequence[m + 1][1]
        v1 = (rm_plus1, -tm_plus1)

        if m + 2 < len(sequence):
            rm_plus2, tm_plus2 = sequence[m + 2][2], sequence[m + 2][1]
        else:
            rm_plus2, tm_plus2 = float("inf"), float("inf")

        v2_candidates = [
            (sequence[m][2], -sequence[m][1]),
            (rm_plus2, -tm_plus2),
        ]
        v2 = min(v2_candidates, key=lambda v: v[0] ** 2 + v[1] ** 2)
        return v1, v2

    def decompose_scalar(self, k: int, n: int) -> Tuple[int, int]:
        if not self.is_enabled:
            return k, 0

        v1, v2 = self.find_short_vectors(n, self.lambda_param)
        v, b1, b2 = self._find_closest_lattice_point(k, v1, v2, n)

        k1 = (k - v[0]) % n
        k2 = (-v[1]) % n
        return k1, k2

    def _find_closest_lattice_point(
        self,
        k: int,
        v1: Tuple[int, int],
        v2: Tuple[int, int],
        n: int,
    ) -> Tuple[Tuple[int, int], int, int]:
        beta1, beta2 = self._compute_beta(k, v1, v2, n)
        b1 = round(beta1)
        b2 = round(beta2)
        v = (
            b1 * v1[0] + b2 * v2[0],
            b1 * v1[1] + b2 * v2[1],
        )
        return v, b1, b2

    def _compute_beta(
        self,
        k: int,
        v1: Tuple[int, int],
        v2: Tuple[int, int],
        n: int,
    ) -> Tuple[float, float]:
        det = v1[0] * v2[1] - v1[1] * v2[0]
        if det == 0:
            return 0.0, 0.0
        A_inv = np.array([[v2[1], -v2[0]], [-v1[1], v1[0]]]) / det
        beta = A_inv @ np.array([k, 0])
        return float(beta[0]), float(beta[1])


DisabledGLV = GLVSpecs(
    is_enabled=False,
    lambda_param=0,
    constant_b=0,
    constant_c=0,
)