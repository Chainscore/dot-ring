from __future__ import annotations

from dot_ring.ring_proof.constants import DEFAULT_SIZE
from dot_ring.ring_proof.params import RingProofParams


def _h_vector(params: RingProofParams, size: int = DEFAULT_SIZE) -> list[tuple[int, int]]:
    """Return `[2⁰·H, 2¹·H, ...]` in short-Weierstrass coords."""
    return [params.mul_point(pow(2, i, params.prime), params.blinding_base) for i in range(size)]


class Ring:
    nm_points: list[tuple[int, int]]
    params: RingProofParams

    def __init__(self, keys: list[bytes], params: RingProofParams | None = None) -> None:
        """
        Initialize a Ring from a list of public keys.

        Args:
            keys: List of public keys (as bytes) for ring members
            params: Ring proof parameters. If None, automatically constructed based on ring size.
        """
        if params is None:
            params = RingProofParams.from_ring_size(len(keys))

        self.params = params

        if len(keys) > params.max_ring_size:
            raise ValueError(f"ring size {len(keys)} exceeds max supported size {params.max_ring_size}")

        self.nm_points = []
        for key in keys:
            if isinstance(key, (str, bytes)):
                point = params.cv.point.string_to_point(key)
                if isinstance(point, str):
                    continue
                self.nm_points.append(params.point_to_ring_point(point))

        while len(self.nm_points) < params.max_ring_size:
            self.nm_points.append(params.padding_point)

        fill_count = params.domain_size - params.padding_rows - len(self.nm_points)
        if fill_count > 0:
            h_vec = _h_vector(params, params.domain_size)
            self.nm_points.extend(h_vec[:fill_count])
        if params.padding_rows > 0:
            self.nm_points.extend([(0, 0)] * params.padding_rows)
