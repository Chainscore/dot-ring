from dataclasses import dataclass
from typing import Any, cast

from dot_ring.ring_proof.columns.columns import Column
from dot_ring.ring_proof.helpers import Helpers as H


@dataclass
class RingRoot:
    px: Column
    py: Column
    s: Column

    def to_bytes(self) -> bytes:
        # Assuming H.bls_g1_compress expects a tuple representation of the commitment
        # and that self.px.commitment, etc., are convertible to such a tuple.
        # If the commitment is already a G1 point object, casting to tuple might be incorrect
        # or require a specific conversion method not shown here.
        # This implementation assumes 'ring_root' refers to the commitments themselves.
        comm_keys = (
            H.bls_g1_compress(cast(Any, self.px.commitment)),  # Cast to Any or a more specific tuple type if known
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
