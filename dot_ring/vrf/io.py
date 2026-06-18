from __future__ import annotations

from dataclasses import dataclass

from dot_ring.curve.point import CurvePoint


@dataclass(frozen=True)
class VrfIo:
    input: CurvePoint
    output: CurvePoint

    def to_bytes(self) -> bytes:
        return self.input.point_to_string() + self.output.point_to_string()
