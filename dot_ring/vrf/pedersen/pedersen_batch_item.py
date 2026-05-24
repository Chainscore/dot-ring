from __future__ import annotations

from dataclasses import dataclass

from dot_ring.curve.point import CurvePoint


@dataclass
class PedersenBatchItem:
    c: int
    input: CurvePoint
    output: CurvePoint
    pk_com: CurvePoint
    r: CurvePoint
    ok: CurvePoint
    s: int
    sb: int
