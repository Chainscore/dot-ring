from dataclasses import dataclass
from functools import cache
from typing import Any, cast

from dot_ring.ring_proof.columns.columns import Column
from dot_ring.ring_proof.constants import DEFAULT_SIZE, S_PRIME, Blinding_Base, PaddingPoint
from dot_ring.ring_proof.curve.bandersnatch import TwistedEdwardCurve as TE
from dot_ring.ring_proof.helpers import Helpers as H
from dot_ring.ring_proof.params import RingProofParams


@cache
def _h_vector(blinding_base: tuple[int, int] = Blinding_Base, size: int = DEFAULT_SIZE) -> list[tuple[int, int]]:
    """Return `[2⁰·H, 2¹·H, …]` in short‑Weierstrass coords."""
    res = [cast(tuple[int, int], TE.mul(pow(2, i, S_PRIME), blinding_base)) for i in range(size)]
    return res


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
        # Auto-construct params if not provided
        if params is None:
            params = RingProofParams.from_ring_size(len(keys))

        self.params = params

        if len(keys) > params.domain_size - params.padding_rows:
            raise ValueError(f"ring size {len(keys)} exceeds max supported size {params.domain_size - params.padding_rows}")

        self.nm_points = []
        for key in keys:
            if isinstance(key, (str, bytes)):
                point = params.cv.point.string_to_point(key)
                if isinstance(point, str):
                    # Handle invalid point string
                    continue
                self.nm_points.append((cast(int, point.x), cast(int, point.y)))
            else:
                # Handle non-string/bytes keys if necessary, or skip/raise
                continue

        # Pad with special point if needed
        while len(self.nm_points) < params.max_ring_size:
            self.nm_points.append(PaddingPoint)

        # Ensure ring size
        fill_count = params.domain_size - params.padding_rows - len(self.nm_points)
        if fill_count > 0:
            h_vec = _h_vector(size=params.domain_size)
            self.nm_points.extend(h_vec[:fill_count])
        if params.padding_rows > 0:
            self.nm_points.extend([(0, 0)] * params.padding_rows)


@dataclass
class RingRoot:
    px: Column
    py: Column
    s: Column

    @classmethod
    def from_ring(cls, ring: Ring, params: RingProofParams):
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
        comm_keys = (
            H.bls_g1_compress(cast(Any, self.px.commitment)),
            H.bls_g1_compress(cast(Any, self.py.commitment)),
            H.bls_g1_compress(cast(Any, self.s.commitment)),
        )
        return bytes.fromhex(comm_keys[0]) + bytes.fromhex(comm_keys[1]) + bytes.fromhex(comm_keys[2])

    @classmethod
    def from_bytes(cls, data: bytes) -> "RingRoot":
        px_commitment = H.bls_g1_decompress(data[0:48].hex())
        py_commitment = H.bls_g1_decompress(data[48:96].hex())
        s_commitment = H.bls_g1_decompress(data[96:144].hex())

        px = Column(name="px", evals=[], commitment=px_commitment)
        py = Column(name="py", evals=[], commitment=py_commitment)
        s = Column(name="s", evals=[], commitment=s_commitment)

        return cls(px=px, py=py, s=s)
