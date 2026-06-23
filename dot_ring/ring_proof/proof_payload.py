from __future__ import annotations

from dataclasses import dataclass

from dot_ring.ring_proof.columns.columns import Column
from dot_ring.ring_proof.params import RingProofParams
from dot_ring.ring_proof.pcs.protocol import G1Commitment

RING_SCALAR_LEN = 32


@dataclass(slots=True)
class RingProofPayload:
    c_b: Column
    c_accip: Column
    c_accx: Column
    c_accy: Column
    px_zeta: int
    py_zeta: int
    s_zeta: int
    b_zeta: int
    accip_zeta: int
    accx_zeta: int
    accy_zeta: int
    c_q: Column
    l_zeta_omega: int
    open_agg_zeta: G1Commitment
    open_l_zeta_omega: G1Commitment

    def as_tuple(
        self,
    ) -> tuple[
        Column,
        Column,
        Column,
        Column,
        int,
        int,
        int,
        int,
        int,
        int,
        int,
        Column,
        int,
        G1Commitment,
        G1Commitment,
    ]:
        return (
            self.c_b,
            self.c_accip,
            self.c_accx,
            self.c_accy,
            self.px_zeta,
            self.py_zeta,
            self.s_zeta,
            self.b_zeta,
            self.accip_zeta,
            self.accx_zeta,
            self.accy_zeta,
            self.c_q,
            self.l_zeta_omega,
            self.open_agg_zeta,
            self.open_l_zeta_omega,
        )

    @staticmethod
    def encoded_len(params: RingProofParams) -> int:
        return 7 * params.pcs.commitment_size + 8 * RING_SCALAR_LEN

    def encode(self, params: RingProofParams) -> bytes:
        return b"".join(
            (
                params.pcs.compress_g1(self.c_b.commitment),
                params.pcs.compress_g1(self.c_accip.commitment),
                params.pcs.compress_g1(self.c_accx.commitment),
                params.pcs.compress_g1(self.c_accy.commitment),
                (self.px_zeta).to_bytes(RING_SCALAR_LEN, "little"),
                (self.py_zeta).to_bytes(RING_SCALAR_LEN, "little"),
                (self.s_zeta).to_bytes(RING_SCALAR_LEN, "little"),
                (self.b_zeta).to_bytes(RING_SCALAR_LEN, "little"),
                (self.accip_zeta).to_bytes(RING_SCALAR_LEN, "little"),
                (self.accx_zeta).to_bytes(RING_SCALAR_LEN, "little"),
                (self.accy_zeta).to_bytes(RING_SCALAR_LEN, "little"),
                params.pcs.compress_g1(self.c_q.commitment),
                (self.l_zeta_omega).to_bytes(RING_SCALAR_LEN, "little"),
                params.pcs.compress_g1(self.open_agg_zeta),
                params.pcs.compress_g1(self.open_l_zeta_omega),
            )
        )

    @classmethod
    def decode(cls, proof: bytes, params: RingProofParams) -> RingProofPayload:
        expected = cls.encoded_len(params)
        if len(proof) != expected:
            raise ValueError(f"invalid Ring VRF proof length: expected {expected}, got {len(proof)}")

        reader = _PayloadReader(proof, params)
        payload = cls(
            c_b=Column(name="c_b", evals=[], _commitment=reader.commitment()),
            c_accip=Column(name="c_accip", evals=[], _commitment=reader.commitment()),
            c_accx=Column(name="c_accx", evals=[], _commitment=reader.commitment()),
            c_accy=Column(name="c_accy", evals=[], _commitment=reader.commitment()),
            px_zeta=reader.scalar(),
            py_zeta=reader.scalar(),
            s_zeta=reader.scalar(),
            b_zeta=reader.scalar(),
            accip_zeta=reader.scalar(),
            accx_zeta=reader.scalar(),
            accy_zeta=reader.scalar(),
            c_q=Column(name="c_q", evals=[], _commitment=reader.commitment()),
            l_zeta_omega=reader.scalar(),
            open_agg_zeta=reader.commitment(),
            open_l_zeta_omega=reader.commitment(),
        )
        reader.finish()
        return payload


class _PayloadReader:
    def __init__(self, data: bytes, params: RingProofParams) -> None:
        self.data = data
        self.params = params
        self.offset = 0

    def commitment(self) -> G1Commitment:
        commitment_size = self.params.pcs.commitment_size
        end = self.offset + commitment_size
        commitment = self.params.pcs.decompress_g1(self.data[self.offset : end])
        self.offset = end
        return commitment

    def scalar(self) -> int:
        end = self.offset + RING_SCALAR_LEN
        value = int.from_bytes(self.data[self.offset : end], "little")
        if value >= self.params.prime:
            raise ValueError("scalar is not canonical")
        self.offset = end
        return value

    def finish(self) -> None:
        if self.offset != len(self.data):
            raise ValueError(f"trailing bytes in ring proof payload: {len(self.data) - self.offset}")
