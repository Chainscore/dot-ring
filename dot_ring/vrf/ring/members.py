"""Ring member preprocessing for the ring-proof public columns (section 3.1).

Invalid or identity keys are normalized to the configured padding point before
fixed columns are built; producer-key lookup remains strict.
"""

from __future__ import annotations

from collections.abc import Sequence

from dot_ring.curve.curve import CurveVariant
from dot_ring.ring_proof.params import RingProofParams
from dot_ring.vrf.codec import point_len


def parse_concatenated_keys(keys: bytes, cv: CurveVariant) -> list[bytes]:
    encoded_point_len = point_len(cv)
    if len(keys) % encoded_point_len != 0:
        raise ValueError(f"invalid concatenated key length: expected multiple of {encoded_point_len}, got {len(keys)}")
    return [keys[encoded_point_len * i : encoded_point_len * (i + 1)] for i in range(len(keys) // encoded_point_len)]


class Ring:
    nm_points: tuple[tuple[int, int], ...]
    params: RingProofParams

    def __init__(self, keys: Sequence[bytes | str], params: RingProofParams | None = None) -> None:
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
            point = self._decode_key(key, padding_point)
            if point is None:
                nm_points.append(padding_point)
                continue
            nm_points.append(point)

        while len(nm_points) < params.max_ring_size:
            nm_points.append(padding_point)

        fill_count = params.domain_size - params.padding_rows - len(nm_points)
        if fill_count > 0:
            nm_points.extend(blinding_base_powers(params, fill_count))
        if params.padding_rows > 0:
            nm_points.extend([(0, 0)] * params.padding_rows)

        self.nm_points = tuple(nm_points)

    def _decode_key(self, key: object, padding_point: tuple[int, int]) -> tuple[int, int] | None:
        if not isinstance(key, (bytes, str)):
            return None
        try:
            point = self.params.cv.point_type.string_to_point(key)
        except ValueError:
            return None
        if point.is_identity():
            return padding_point
        return int(point.x), int(point.y)

    def index_of(self, key: bytes | str) -> int:
        padding_point = self.params.cv.curve.params.auxiliary_points.padding_point
        point = self._decode_key(key, padding_point)
        if point is None:
            raise ValueError("invalid ring key")
        if point == padding_point:
            raise ValueError("producer key is not in ring")
        try:
            return self.nm_points[: self.params.max_ring_size].index(point)
        except ValueError as exc:
            raise ValueError("producer key is not in ring") from exc


def blinding_base_powers(params: RingProofParams, count: int) -> tuple[tuple[int, int], ...]:
    point = params.cv.curve.params.auxiliary_points.blinding_base
    points = []
    for _ in range(count):
        points.append(point)
        point_obj = params.cv.point_type(*point)
        doubled = point_obj + point_obj
        point = int(doubled.x), int(doubled.y)
    return tuple(points)
