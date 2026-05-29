from dataclasses import dataclass
from functools import cache
from typing import Any, cast

from dot_ring.ring_proof.columns.columns import Column
from dot_ring.ring_proof.constants import DEFAULT_SIZE, S_PRIME, Blinding_Base, PaddingPoint
from dot_ring.ring_proof.curve.bandersnatch import TwistedEdwardCurve as TE
from dot_ring.ring_proof.helpers import Helpers as H
from dot_ring.ring_proof.params import RingProofParams

BLS_G1_LEN = 48
RING_ROOT_LEN = BLS_G1_LEN * 3


@cache
def _h_vector(blinding_base: tuple[int, int] = Blinding_Base, size: int = DEFAULT_SIZE) -> list[tuple[int, int]]:
    """Return `[2⁰·H, 2¹·H, …]` in short‑Weierstrass coords."""
    res = [cast(tuple[int, int], TE.mul(pow(2, i, S_PRIME), blinding_base)) for i in range(size)]
    return res


def _ring_point_or_padding(key: bytes, params: RingProofParams) -> tuple[int, int]:
    try:
        point = params.cv.point.string_to_point(key)
    except Exception:
        return PaddingPoint
    if isinstance(point, str) or point.is_identity():
        return PaddingPoint
    return (cast(int, point.x), cast(int, point.y))


class Ring:
    nm_points: list[tuple[int, int]]
    params: RingProofParams

    def __init__(self, keys: list[bytes], params: RingProofParams | None = None) -> None:
        """
        Initialize a Ring from a list of public keys.

        Args:
            keys: List of public keys (as bytes) for ring members
            params: Ring proof parameters. If None, automatically constructed based on ring size.

        Example:
            >>> # Auto-construct params based on ring size
            >>> ring = Ring(keys)  # Will use appropriate domain size
            >>>
            >>> # Or specify params explicitly
            >>> params = RingProofParams(domain_size=2048, max_ring_size=1023)
            >>> ring = Ring(keys, params)
        """
        if params is None:
            params = RingProofParams.from_ring_size(len(keys))
        self.params = params

        if len(keys) > params.max_ring_size:
            raise ValueError(f"ring size {len(keys)} exceeds max supported size {params.max_ring_size}")

        self.nm_points = [_ring_point_or_padding(key, params) for key in keys]
        self.nm_points.extend([PaddingPoint] * (params.max_ring_size - len(self.nm_points)))

        fill_count = params.domain_size - params.padding_rows - len(self.nm_points)
        if fill_count > 0:
            self.nm_points.extend(_h_vector(size=params.domain_size)[:fill_count])
        if params.padding_rows > 0:
            self.nm_points.extend([(0, 0)] * params.padding_rows)


@dataclass
class RingRoot:
    px: Column
    py: Column
    s: Column

    @classmethod
    def from_ring(cls, ring: Ring, params: RingProofParams | None = None):
        if params is None:
            params = ring.params
        # Px, Py, s points
        px, py = H.unzip(ring.nm_points)
        selector_vec = [1 if i < params.max_ring_size else 0 for i in range(params.domain_size)]
        # Columns
        px_col = Column("Px", px, size=params.domain_size)
        py_col = Column("Py", py, size=params.domain_size)
        s_col = Column("s", selector_vec, size=params.domain_size)
        for col in (px_col, py_col, s_col):
            col.interpolate(params.omega, params.prime)
            col.commit()
        return cls(px=px_col, py=py_col, s=s_col)

    def to_bytes(self) -> bytes:
        for col in (self.px, self.py, self.s):
            if col.commitment is None:
                raise ValueError("Ring root is missing commitments")
        comm_keys = (
            H.bls_g1_compress(cast(Any, self.px.commitment)),
            H.bls_g1_compress(cast(Any, self.py.commitment)),
            H.bls_g1_compress(cast(Any, self.s.commitment)),
        )
        return bytes.fromhex(comm_keys[0]) + bytes.fromhex(comm_keys[1]) + bytes.fromhex(comm_keys[2])

    @classmethod
    def from_bytes(cls, data: bytes) -> "RingRoot":
        H.require_length(data, RING_ROOT_LEN, "ring root")
        px_commitment = H.bls_g1_decompress(data[0:BLS_G1_LEN].hex())
        py_commitment = H.bls_g1_decompress(data[BLS_G1_LEN : BLS_G1_LEN * 2].hex())
        s_commitment = H.bls_g1_decompress(data[BLS_G1_LEN * 2 : RING_ROOT_LEN].hex())

        px = Column(name="px", evals=[], commitment=px_commitment)
        py = Column(name="py", evals=[], commitment=py_commitment)
        s = Column(name="s", evals=[], commitment=s_commitment)

        return cls(px=px, py=py, s=s)
