from __future__ import annotations

from collections.abc import Sequence
from functools import lru_cache
from typing import Any

from dot_ring.ring_proof.constants import DEFAULT_SIZE
from dot_ring.ring_proof.params import RingProofParams


@lru_cache(maxsize=32)
def _h_vector_cached(
    blinding_base: tuple[int, int],
    size: int,
    point_cls: type[Any],
) -> tuple[tuple[int, int], ...]:
    point = blinding_base
    points = []
    for _ in range(size):
        points.append(point)
        point_obj = point_cls(point[0], point[1])
        result = point_obj + point_obj
        point = int(result.x), int(result.y)
    return tuple(points)


def _h_vector(params: RingProofParams, size: int = DEFAULT_SIZE) -> list[tuple[int, int]]:
    """Return `[2⁰·H, 2¹·H, ...]` in short-Weierstrass coords."""
    return list(_h_vector_cached(params.blinding_base, size, params.ring_point_cls))


class Ring:
    nm_points: list[tuple[int, int]]
    params: RingProofParams
    key_index: dict[tuple[int, int], int]

    def __init__(self, keys: Sequence[bytes | str], params: RingProofParams | None = None) -> None:
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
        self.key_index = {}
        for key in keys:
            point = self._decode_key(key)
            if point is None:
                continue
            self.key_index.setdefault(point, len(self.nm_points))
            self.nm_points.append(point)

        while len(self.nm_points) < params.max_ring_size:
            self.nm_points.append(params.padding_point)

        fill_count = params.domain_size - params.padding_rows - len(self.nm_points)
        if fill_count > 0:
            h_vec = _h_vector(params, params.domain_size)
            self.nm_points.extend(h_vec[:fill_count])
        if params.padding_rows > 0:
            self.nm_points.extend([(0, 0)] * params.padding_rows)

    def _decode_key(self, key: object) -> tuple[int, int] | None:
        if not isinstance(key, (bytes, str)):
            return None
        try:
            point = self.params.cv.point.string_to_point(key)
        except ValueError:
            return None
        if point.is_identity():
            return self.params.padding_point
        return self.params.point_to_ring_point(point)

    def index_of(self, key: bytes | str) -> int:
        point = self._decode_key(key)
        if point is None:
            raise ValueError("invalid ring key")
        try:
            return self.key_index[point]
        except KeyError as exc:
            raise ValueError("producer key is not in ring") from exc
