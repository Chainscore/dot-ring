from dataclasses import dataclass
from dot_ring.ring_proof.columns.columns import Column
from dot_ring.ring_proof.helpers import Helpers as H


@dataclass
class RingRoot:
    px: Column
    py: Column
    s: Column
    
    def to_bytes(self) -> bytes:
        return (
            bytes.fromhex(H.bls_g1_compress(self.px.commitment))
            + bytes.fromhex(H.bls_g1_compress(self.py.commitment))
            + bytes.fromhex(H.bls_g1_compress(self.s.commitment))
        )
        
    @classmethod
    def from_bytes(cls, data: bytes) -> "RingRoot":
        px_commitment = H.bls_g1_decompress(data[0:48].hex())
        py_commitment = H.bls_g1_decompress(data[48:96].hex())
        s_commitment = H.bls_g1_decompress(data[96:144].hex())
        
        ring_root = cls()
        ring_root.px = Column(name="px", evals=[], commitment=px_commitment)
        ring_root.py = Column(name="py", evals=[], commitment=py_commitment)
        ring_root.s = Column(name="s", evals=[], commitment=s_commitment)
        
        return ring_root