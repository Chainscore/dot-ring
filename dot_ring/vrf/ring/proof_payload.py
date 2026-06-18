from __future__ import annotations

from dataclasses import dataclass

from dot_ring.ring_proof.columns.columns import Column, require_commitment
from dot_ring.ring_proof.params import RingProofParams
from dot_ring.ring_proof.pcs.opening import Opening
from dot_ring.ring_proof.pcs.protocol import G1Commitment

RING_SCALAR_LEN = 32


def ring_proof_len(params: RingProofParams) -> int:
    return 7 * params.pcs.commitment_size + 8 * RING_SCALAR_LEN


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
    open_agg_zeta: Opening
    open_l_zeta_omega: Opening

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
        Opening,
        Opening,
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

    def to_bytes(self, params: RingProofParams) -> bytes:
        return b"".join(
            (
                params.pcs.compress_g1(require_commitment(self.c_b)),
                params.pcs.compress_g1(require_commitment(self.c_accip)),
                params.pcs.compress_g1(require_commitment(self.c_accx)),
                params.pcs.compress_g1(require_commitment(self.c_accy)),
                _scalar_to_bytes(self.px_zeta),
                _scalar_to_bytes(self.py_zeta),
                _scalar_to_bytes(self.s_zeta),
                _scalar_to_bytes(self.b_zeta),
                _scalar_to_bytes(self.accip_zeta),
                _scalar_to_bytes(self.accx_zeta),
                _scalar_to_bytes(self.accy_zeta),
                params.pcs.compress_g1(require_commitment(self.c_q)),
                _scalar_to_bytes(self.l_zeta_omega),
                params.pcs.compress_g1(self.open_agg_zeta.proof),
                params.pcs.compress_g1(self.open_l_zeta_omega.proof),
            )
        )

    @classmethod
    def from_bytes(cls, proof: bytes, params: RingProofParams) -> RingProofPayload:
        expected = ring_proof_len(params)
        if len(proof) != expected:
            raise ValueError(f"invalid Ring VRF proof length: expected {expected}, got {len(proof)}")

        reader = _PayloadReader(proof, params)
        return cls(
            c_b=Column(name="c_b", evals=[], commitment=reader.commitment()),
            c_accip=Column(name="c_accip", evals=[], commitment=reader.commitment()),
            c_accx=Column(name="c_accx", evals=[], commitment=reader.commitment()),
            c_accy=Column(name="c_accy", evals=[], commitment=reader.commitment()),
            px_zeta=reader.scalar(),
            py_zeta=reader.scalar(),
            s_zeta=reader.scalar(),
            b_zeta=reader.scalar(),
            accip_zeta=reader.scalar(),
            accx_zeta=reader.scalar(),
            accy_zeta=reader.scalar(),
            c_q=Column(name="c_q", evals=[], commitment=reader.commitment()),
            l_zeta_omega=reader.scalar(),
            open_agg_zeta=Opening(proof=reader.commitment(), y=0),
            open_l_zeta_omega=Opening(proof=reader.commitment(), y=0),
        )


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
        end = self.offset + 32
        value = _scalar_from_bytes(self.data[self.offset : end], self.params.prime)
        self.offset = end
        return value


def _scalar_to_bytes(value: int) -> bytes:
    return value.to_bytes(RING_SCALAR_LEN, "little")


def _scalar_from_bytes(data: bytes, modulus: int) -> int:
    if len(data) != RING_SCALAR_LEN:
        raise ValueError(f"scalar must be exactly {RING_SCALAR_LEN} bytes, got {len(data)}")
    value = int.from_bytes(data, "little")
    if value >= modulus:
        raise ValueError("scalar is not canonical")
    return value
