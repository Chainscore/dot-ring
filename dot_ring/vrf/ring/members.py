"""Ring member preprocessing for the ring-proof public columns (section 3.1).

Invalid or identity keys are normalized to the configured padding point before
fixed columns are built; producer-key lookup remains strict.
"""

from __future__ import annotations

from collections.abc import Sequence
from functools import lru_cache

from dot_ring.ring_proof.params import RingProofParams
from dot_ring.vrf.codec import dec_point

ParamsCacheKey = tuple[int, int, int, int | None, int, int, bool, int, int]


class Ring:
    nm_points: tuple[tuple[int, int], ...]
    params: RingProofParams

    def __init__(self, keys: Sequence[bytes], params: RingProofParams | None = None) -> None:
        """Build spec public vector `PK || B powers || zero padding` from encoded keys."""
        if params is None:
            params = RingProofParams.from_ring_size(len(keys))

        self.params = params
        padding_point = params.cv.curve.params.auxiliary_points.padding_point
        if not padding_point:
            raise ValueError("padding point is not configured in curve parameters")

        if len(keys) > params.max_ring_size:
            raise ValueError(f"ring size {len(keys)} exceeds max supported size {params.max_ring_size}")

        nm_points: list[tuple[int, int]] = []
        for key in keys:
            point = self._decode_key(key)
            if point is None:
                nm_points.append(padding_point)
                continue
            nm_points.append(point)

        while len(nm_points) < params.max_ring_size:
            nm_points.append(padding_point)

        fill_count = params.domain_size - params.padding_rows - len(nm_points)
        if fill_count > 0:
            blinding_base = params.cv.curve.params.auxiliary_points.blinding_base
            if not blinding_base:
                raise ValueError("blinding base is not configured in curve parameters")
            nm_points.extend(_blinding_base_powers(params.cv.point_type, blinding_base, fill_count))
        if params.padding_rows > 0:
            nm_points.extend([(0, 0)] * params.padding_rows)

        self.nm_points = tuple(nm_points)

    @classmethod
    def from_keys(cls, keys: Sequence[bytes], params: RingProofParams | None = None) -> Ring:
        """Return a cached ring for a stable encoded key vector."""
        return _ring(tuple(bytes(key) for key in keys))

    def _decode_key(self, key: bytes) -> tuple[int, int] | None:
        try:
            point = dec_point(self.params.cv, key)
        except ValueError:
            return None
        if point.is_identity():
            return None
        return int(point.x), int(point.y)

    def index_of(self, key: bytes) -> int:
        padding_point = self.params.cv.curve.params.auxiliary_points.padding_point
        point = self._decode_key(key)
        if point is None:
            raise ValueError("invalid ring key")
        if point == padding_point:
            raise ValueError("producer key is not in ring")
        try:
            return self.nm_points[: self.params.max_ring_size].index(point)
        except ValueError as exc:
            raise ValueError("producer key is not in ring") from exc


@lru_cache(maxsize=8)
def _blinding_base_powers(point_type: type, blinding_base: tuple[int, int], count: int) -> tuple[tuple[int, int], ...]:
    points: list[tuple[int, int]] = []
    point = point_type(*blinding_base)
    for _ in range(count):
        points.append((int(point.x), int(point.y)))
        point = point + point
    return tuple(points)


@lru_cache(maxsize=2)
def _params(keys_len: int) -> RingProofParams:
    return RingProofParams.from_ring_size(keys_len)


@lru_cache(maxsize=8)
def _ring(keys: tuple[bytes, ...]) -> Ring:
    return Ring(keys, _params(len(keys)))
