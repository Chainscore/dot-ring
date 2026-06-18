from __future__ import annotations

from collections.abc import Sequence
from functools import lru_cache

from dot_ring.curve.curve import CurveVariant
from dot_ring.ring_proof.params import RingProofParams
from dot_ring.vrf.transcript import point_len


def parse_concatenated_keys(keys: bytes, cv: CurveVariant) -> list[bytes]:
    encoded_point_len = point_len(cv)
    if len(keys) % encoded_point_len != 0:
        raise ValueError(f"invalid concatenated key length: expected multiple of {encoded_point_len}, got {len(keys)}")
    return [keys[encoded_point_len * i : encoded_point_len * (i + 1)] for i in range(len(keys) // encoded_point_len)]


def blinding_base_powers(params: RingProofParams, count: int) -> tuple[tuple[int, int], ...]:
    def _bb_cache_key(params: RingProofParams) -> tuple[str, int, int, int, tuple[int, int]]:
        return (
            params.ring_curve_variant().name,
            params.prime,
            params.ring_edwards_a,
            params.ring_edwards_d,
            params.blinding_base,
        )

    return _blinding_base_powers(params, _bb_cache_key(params), count)


@lru_cache(maxsize=16)
def _blinding_base_powers(
    params: RingProofParams,
    _cache_key: tuple[str, int, int, int, tuple[int, int]],
    count: int,
) -> tuple[tuple[int, int], ...]:
    """Return `[2^0 * H, 2^1 * H, ...]` in ring coordinates."""
    point = params.blinding_base
    points = []
    for _ in range(count):
        points.append(point)
        point_obj = params.ring_point(point)
        result = point_obj + point_obj
        point = int(result.x), int(result.y)
    return tuple(points)


class Ring:
    nm_points: tuple[tuple[int, int], ...]
    params: RingProofParams

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

        nm_points: list[tuple[int, int]] = []
        for key in keys:
            point = self._decode_key(key)
            if point is None:
                nm_points.append(params.padding_point)
                continue
            nm_points.append(point)

        while len(nm_points) < params.max_ring_size:
            nm_points.append(params.padding_point)

        fill_count = params.domain_size - params.padding_rows - len(nm_points)
        if fill_count > 0:
            nm_points.extend(blinding_base_powers(params, fill_count))
        if params.padding_rows > 0:
            nm_points.extend([(0, 0)] * params.padding_rows)

        self.nm_points = tuple(nm_points)

    def _decode_key(self, key: object) -> tuple[int, int] | None:
        if not isinstance(key, (bytes, str)):
            return None
        try:
            point = self.params.cv.string_to_point(key)
        except ValueError:
            return None
        if point.is_identity():
            return self.params.padding_point
        return self.params.point_to_ring_point(point)

    def index_of(self, key: bytes | str) -> int:
        point = self._decode_key(key)
        if point is None:
            raise ValueError("invalid ring key")
        if point == self.params.padding_point:
            raise ValueError("producer key is not in ring")
        try:
            return self.nm_points[: self.params.max_ring_size].index(point)
        except ValueError as exc:
            raise ValueError("producer key is not in ring") from exc
