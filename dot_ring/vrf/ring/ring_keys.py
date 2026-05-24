from __future__ import annotations

from dot_ring.curve.curve import CurveVariant


def parse_concatenated_keys(keys: bytes, cv: CurveVariant) -> list[bytes]:
    point_len = cv.curve.POINT_LEN * (2 if cv.curve.UNCOMPRESSED else 1)
    if len(keys) % point_len != 0:
        raise ValueError(f"invalid concatenated key length: expected multiple of {point_len}, got {len(keys)}")
    return [keys[point_len * i : point_len * (i + 1)] for i in range(len(keys) // point_len)]
