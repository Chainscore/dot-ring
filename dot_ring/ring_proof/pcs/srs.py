from __future__ import annotations

import os
from collections.abc import Sequence
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import cast

from py_ecc.optimized_bls12_381 import FQ, FQ2

from dot_ring import blst

from .utils import g1_to_blst, g2_to_blst


def _candidate_srs_files(min_g1_count: int) -> list[Path]:
    base_dir = Path(__file__).resolve().parent
    candidates = []
    env_path = os.environ.get("DOT_RING_BLS12_381_SRS")
    if env_path:
        candidates.append(Path(env_path))
    candidates.append(base_dir.parent.parent / "vrf" / "data" / "bls12-381-srs-2-11-uncompressed-zcash.bin")
    candidates.append(base_dir.parent.parent / "vrf" / "data" / "bls12-381-srs-2-16-uncompressed-zcash.bin")

    workspace_root = base_dir.parents[3] if len(base_dir.parents) > 3 else None
    if workspace_root is not None:
        candidates.append(workspace_root / "docs" / "bandersnatch-vrf-spec" / "assets" / "srs" / "zcash-srs-2-16-uncompressed.bin")
        candidates.append(workspace_root / "ark-vrf" / "data" / "srs" / "bls12-381-srs-2-16-uncompressed-zcash.bin")

    usable = []
    for candidate in candidates:
        if not candidate.exists():
            continue
        with open(candidate, "rb") as f:
            header = f.read(8)
        if len(header) == 8 and int.from_bytes(header, byteorder="little") >= min_g1_count:
            usable.append(candidate)
    return usable


def read_srs_file(g1_limit: int | None = None) -> tuple[list[tuple[int, int]], list[tuple[tuple[int, int], tuple[int, int]]]]:
    min_g1_count = g1_limit or 1
    candidates = _candidate_srs_files(min_g1_count)
    if not candidates:
        raise ValueError(f"no BLS12-381 SRS file with at least {min_g1_count} G1 points is available")

    filename = candidates[0]
    with open(filename, "rb") as f:
        header = f.read(8)
        # The first 8 bytes form a little-endian uint64 that gives the number of G1 elements.
        if len(header) < 8:
            raise ValueError("File too short to contain header.")
        g1_count = int.from_bytes(header, byteorder="little")
        read_g1_count = g1_count if g1_limit is None else min(g1_limit, g1_count)

        G1_POINT_SIZE = 96  # 2 * 48-byte field elements.
        G1_points = []
        for i in range(read_g1_count):
            point_bytes = f.read(G1_POINT_SIZE)
            if len(point_bytes) != G1_POINT_SIZE:
                raise ValueError(f"Unexpected end-of-file when reading G1 point {i}.")
            x_bytes = point_bytes[:48]
            y_bytes = point_bytes[48:]
            x = int.from_bytes(x_bytes, byteorder="big")
            y = int.from_bytes(y_bytes, byteorder="big")
            G1_points.append((x, y))

        f.seek(8 + g1_count * G1_POINT_SIZE)
        g2_count_raw = f.read(8)
        if len(g2_count_raw) < 8:
            raise ValueError("File too short to contain G2 vector length header.")

        g2_count = int.from_bytes(g2_count_raw, byteorder="little")
        if g2_count < 2:
            raise ValueError("SRS file must contain at least two G2 points")

        G2_POINT_SIZE = 192  # 2 coordinates, each with 2*48 bytes.
        G2_points = []
        for i in range(2):
            point_bytes = f.read(G2_POINT_SIZE)
            if len(point_bytes) != G2_POINT_SIZE:
                raise ValueError(f"Unexpected end-of-file when reading G2 point {i}.")
            x0 = int.from_bytes(point_bytes[0:48], byteorder="big")
            x1 = int.from_bytes(point_bytes[48:96], byteorder="big")
            y0 = int.from_bytes(point_bytes[96:144], byteorder="big")
            y1 = int.from_bytes(point_bytes[144:192], byteorder="big")
            G2_points.append(((x1, x0), (y1, y0)))

    return G1_points, G2_points


G1Point = tuple[FQ, FQ, FQ]
G2Point = tuple[FQ2, FQ2, FQ2]


@dataclass()
class SRS:
    g1: Sequence[G1Point]
    g2: Sequence[G2Point]
    g1_points: Sequence[tuple[int, int]]
    g2_points: Sequence[tuple[tuple[int, int], tuple[int, int]]]
    blst_g1: Sequence[blst.P1]
    blst_g1_memory: memoryview
    blst_g2: Sequence[blst.P2]

    def __init__(self, g1_raw: list, g2_raw: list, g1_points: list, g2_points: list) -> None:
        self.g1 = [self._to_jacobian_g1(p) for p in g1_raw]
        self.g2 = [self._to_jacobian_g2(p) for p in g2_raw[:2]]
        self.g1_points = g1_points
        self.g2_points = g2_points
        self.blst_g1 = [g1_to_blst(p) for p in self.g1]
        self.blst_g1_memory = blst.P1_Affines.as_memory(self.blst_g1)
        self.blst_g2 = [g2_to_blst(p) for p in self.g2]

    @classmethod
    def _to_jacobian_g1(cls, pt: tuple | list) -> G1Point:
        """(x, y) | (int, int)  →  (FQ, FQ, FQ_one)."""
        if len(pt) == 3:  # already projective
            return cast(G1Point, pt)
        x, y = pt
        return FQ(x), FQ(y), FQ.one()

    @classmethod
    def _to_jacobian_g2(cls, pt: tuple | list) -> G2Point:
        if len(pt) == 3:
            return cast(G2Point, pt)
        x, y = pt
        res = (FQ2([x[0], x[1]]), FQ2([y[0], y[1]]), FQ2([1, 0]))
        return res

    @classmethod
    def from_loaded(cls, max_deg: int) -> SRS:
        g1_points, g2_points = read_srs_file(max_deg + 1)

        g1_jac = [cls._to_jacobian_g1(p) for p in g1_points[: max_deg + 1]]
        # G2 only needs two powers: 1 and Tau
        g2_jac = [cls._to_jacobian_g2(p) for p in g2_points[:2]]
        return cls(g1_jac, g2_jac, g1_points=g1_points, g2_points=g2_points)

    # Global bounded cache: loaded SRS objects are immutable and keyed by max degree.
    @staticmethod
    @lru_cache(maxsize=2)
    def default(max_deg: int = 6144) -> SRS:
        return SRS.from_loaded(max_deg)


srs = SRS.default()
