from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

import py_ecc.optimized_bn128 as bn254  # type: ignore[import-untyped]

from .bn254_serialization import read_field

BN254_G1Point = Any
BN254_G2Point = Any


@dataclass()
class BN254SRS:
    g1: list[BN254_G1Point]
    g2: list[BN254_G2Point]
    g1_points: list[tuple[int, int]]
    g2_points: list[tuple[tuple[int, int], tuple[int, int]]]
    g1_uncompressed: list[bytes]
    g2_uncompressed: list[bytes]

    @classmethod
    def from_file(cls) -> BN254SRS:
        filename = Path(__file__).resolve().parent.parent.parent / "vrf" / "data" / "bn254-testing-2-9-uncompressed.bin"
        data = filename.read_bytes()
        if len(data) < 8:
            raise ValueError("BN254 SRS file too short")
        g1_count = int.from_bytes(data[:8], "little")
        offset = 8

        g1: list[BN254_G1Point] = []
        g1_points: list[tuple[int, int]] = []
        g1_uncompressed: list[bytes] = []
        for i in range(g1_count):
            raw = data[offset : offset + 64]
            if len(raw) != 64:
                raise ValueError(f"unexpected end of BN254 SRS while reading G1 point {i}")
            offset += 64
            x, _ = read_field(raw[:32])
            y, _ = read_field(raw[32:], flags=True)
            point = (bn254.FQ(x), bn254.FQ(y), bn254.FQ(1))
            if not bn254.is_on_curve(point, bn254.b):
                raise ValueError(f"invalid BN254 SRS G1 point {i}")
            g1.append(point)
            g1_points.append((x, y))
            g1_uncompressed.append(raw)

        if len(data) < offset + 8:
            raise ValueError("BN254 SRS file missing G2 count")
        g2_count = int.from_bytes(data[offset : offset + 8], "little")
        offset += 8

        g2: list[BN254_G2Point] = []
        g2_points: list[tuple[tuple[int, int], tuple[int, int]]] = []
        g2_uncompressed: list[bytes] = []
        for i in range(g2_count):
            raw = data[offset : offset + 128]
            if len(raw) != 128:
                raise ValueError(f"unexpected end of BN254 SRS while reading G2 point {i}")
            offset += 128
            x0, _ = read_field(raw[0:32])
            x1, _ = read_field(raw[32:64])
            y0, _ = read_field(raw[64:96])
            y1, _ = read_field(raw[96:128], flags=True)
            point = (bn254.FQ2([x0, x1]), bn254.FQ2([y0, y1]), bn254.FQ2([1, 0]))
            if not bn254.is_on_curve(point, bn254.b2):
                raise ValueError(f"invalid BN254 SRS G2 point {i}")
            g2.append(point)
            g2_points.append(((x1, x0), (y1, y0)))
            g2_uncompressed.append(raw)

        return cls(
            g1=g1,
            g2=g2[:2],
            g1_points=g1_points,
            g2_points=g2_points,
            g1_uncompressed=g1_uncompressed,
            g2_uncompressed=g2_uncompressed[:2],
        )

    @staticmethod
    @lru_cache(maxsize=1)
    def default() -> BN254SRS:
        return BN254SRS.from_file()
