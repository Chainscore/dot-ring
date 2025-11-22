from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from typing import Sequence, Tuple
from py_ecc.optimized_bls12_381 import FQ, FQ2
from .utils import (
    py_ecc_point_to_blst,
    py_ecc_g2_point_to_blst,
    convert_g1_point_to_blst,
)
from pathlib import Path
import blst


def read_srs_file():
    base_dir = Path(__file__).resolve().parent
    filename = (
        base_dir.parent.parent
        / "vrf"
        / "data"
        / "bls12-381-srs-2-11-uncompressed-zcash.bin"
    )
    with open(filename, "rb") as f:
        data = f.read()

    # The first 8 bytes form a little-endian uint64 that gives the number of G1 elements.
    if len(data) < 8:
        raise ValueError("File too short to contain header.")
    header = data[:8]
    g1_count = int.from_bytes(header, byteorder="little")

    offset = 8
    G1_POINT_SIZE = 96  # 2 * 48-byte field elements.
    G1_points = []
    for i in range(g1_count):
        point_bytes = data[offset : offset + G1_POINT_SIZE]
        if len(point_bytes) != G1_POINT_SIZE:
            raise ValueError(f"Unexpected end-of-file when reading G1 point {i}.")
        x_bytes = point_bytes[:48]
        y_bytes = point_bytes[48:]
        x = int.from_bytes(x_bytes, byteorder="big")
        y = int.from_bytes(y_bytes, byteorder="big")
        G1_points.append((x, y))
        offset += G1_POINT_SIZE

    if len(data) < offset + 8:
        raise ValueError("File too short to contain G2 vector length header.")

    g2_count = int.from_bytes(data[offset : offset + 8], byteorder="little")
    offset += 8

    G2_POINT_SIZE = 192  # 2 coordinates, each with 2*48 bytes.
    G2_points = []
    for i in range(g2_count):
        point_bytes = data[offset : offset + G2_POINT_SIZE]
        if len(point_bytes) != G2_POINT_SIZE:
            raise ValueError(f"Unexpected end-of-file when reading G2 point {i}.")
        x0 = int.from_bytes(point_bytes[0:48], byteorder="big")
        x1 = int.from_bytes(point_bytes[48:96], byteorder="big")
        y0 = int.from_bytes(point_bytes[96:144], byteorder="big")
        y1 = int.from_bytes(point_bytes[144:192], byteorder="big")
        G2_points.append(((x1, x0), (y1, y0)))
        offset += G2_POINT_SIZE

    return G1_points, G2_points


G1Point = Tuple[FQ, FQ, FQ]
G2Point = Tuple[FQ2, FQ2, FQ2]


@dataclass()
class SRS:
    g1: Sequence[G1Point]
    g2: Sequence[G2Point]
    g1_points: Sequence[Tuple[int, int]] 
    g2_points: Sequence[Tuple[Tuple[int, int], Tuple[int, int]]] 
    blst_g1: Sequence[blst.P1]
    blst_sw_g1: Sequence[blst.P1]
    blst_g2: Sequence[blst.P2]

    def __init__(self, g1_raw, g2_raw, g1_points, g2_points):
        self.g1 = [self._to_jacobian_g1(p) for p in g1_raw]
        self.g2 = [self._to_jacobian_g2(p) for p in g2_raw[:2]]
        self.g1_points = g1_points
        self.g2_points = g2_points
        self.blst_g1 = [py_ecc_point_to_blst(p) for p in self.g1]
        self.blst_sw_g1 = [convert_g1_point_to_blst(p) for p in self.g1]
        # Cache G2 points for verification
        self.blst_g2 = [py_ecc_g2_point_to_blst(p) for p in self.g2]

    @classmethod
    def _to_jacobian_g1(cls, pt) -> G1Point:
        """(x, y) | (int, int)  →  (FQ, FQ, FQ_one)."""
        if len(pt) == 3:  # already projective
            return pt
        x, y = pt
        return FQ(x), FQ(y), FQ.one()

    @classmethod
    def _to_jacobian_g2(cls, pt) -> G2Point:
        if len(pt) == 3:
            return pt
        x, y = pt
        res = (FQ2([x[0], x[1]]), FQ2([y[0], y[1]]), FQ2([1, 0]))
        return res

    @classmethod
    def from_loaded(cls, max_deg: int) -> "SRS":
        g1_points, g2_points = read_srs_file()

        if max_deg >= len(g1_points):
            raise ValueError("polynomial degree exceeds available SRS length")

        g1_jac = [cls._to_jacobian_g1(p) for p in g1_points[: max_deg + 1]]
        # G2 only needs two powers: 1 and Tau
        g2_jac = [cls._to_jacobian_g2(p) for p in g2_points[:2]]
        return cls(g1_jac, g2_jac, g1_points=g1_points, g2_points=g2_points)

    @staticmethod
    @lru_cache(maxsize=None)
    def default(max_deg: int = 2048) -> "SRS":
        return SRS.from_loaded(max_deg)

srs = SRS.default()