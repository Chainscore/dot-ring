from dataclasses import dataclass
from typing import Any, cast

from dot_ring.ring_proof.columns.columns import Column
from dot_ring.ring_proof.helpers import Helpers as H
from dot_ring.ring_proof.params import RingProofParams
from dot_ring.ring_proof.pcs.bn254_kzg import BN254KZG

from .ring import Ring


@dataclass
class RingRoot:
    px: Column
    py: Column
    s: Column
    params: RingProofParams | None = None

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
            col.commit(params.pcs)
        return cls(px=px_col, py=py_col, s=s_col, params=params)

    def to_bytes(self) -> bytes:
        pcs = self.params.pcs if self.params is not None else None
        if pcs is not None and getattr(pcs, "commitment_size", 48) == 32:
            return b"".join(
                (
                    pcs.compress_g1(cast(Any, self.px.commitment)),
                    pcs.compress_g1(cast(Any, self.py.commitment)),
                    pcs.compress_g1(cast(Any, self.s.commitment)),
                )
            )
        comm_keys = (
            H.bls_g1_compress(cast(Any, self.px.commitment)),
            H.bls_g1_compress(cast(Any, self.py.commitment)),
            H.bls_g1_compress(cast(Any, self.s.commitment)),
        )
        return bytes.fromhex(comm_keys[0]) + bytes.fromhex(comm_keys[1]) + bytes.fromhex(comm_keys[2])

    @classmethod
    def from_bytes(cls, data: bytes, params: RingProofParams | None = None) -> "RingRoot":
        if params is not None:
            commitment_size = params.pcs.commitment_size
        else:
            commitment_size = 32 if len(data) == 96 else 48
        expected = 3 * commitment_size
        if len(data) != expected:
            raise ValueError(f"invalid ring root length: expected {expected}, got {len(data)}")
        if commitment_size == 32:
            pcs = params.pcs if params is not None else BN254KZG
            px_commitment = pcs.decompress_g1(data[0:32])
            py_commitment = pcs.decompress_g1(data[32:64])
            s_commitment = pcs.decompress_g1(data[64:96])
        else:
            px_commitment = H.bls_g1_decompress(data[0:48].hex())
            py_commitment = H.bls_g1_decompress(data[48:96].hex())
            s_commitment = H.bls_g1_decompress(data[96:144].hex())

        px = Column(name="px", evals=[], commitment=px_commitment)
        py = Column(name="py", evals=[], commitment=py_commitment)
        s = Column(name="s", evals=[], commitment=s_commitment)

        return cls(px=px, py=py, s=s, params=params)
