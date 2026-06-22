from dataclasses import dataclass
from functools import lru_cache
from typing import Any

from dot_ring.ring_proof.columns.columns import Column, require_commitment
from dot_ring.ring_proof.params import RingProofParams
from dot_ring.ring_proof.pcs.kzg import KZG
from dot_ring.ring_proof.transcript.phases import serialize_verifier_key
from dot_ring.ring_proof.transcript.transcript import FiatShamirTranscript

from .members import Ring


# Note: [Assumption] Selector column would likely be same as long as ring size doesn't change
@lru_cache(maxsize=4)
def _selector_column_data(
    domain_size: int,
    max_ring_size: int,
    omega: int,
    prime: int,
    pcs: Any,
) -> tuple[tuple[int, ...], tuple[int, ...], Any]:
    selector_vec = [1 if i < max_ring_size else 0 for i in range(domain_size)]
    selector_col = Column("s", selector_vec, size=domain_size)
    selector_col.interpolate(omega, prime)
    selector_col.commit(pcs)
    if selector_col.coeffs is None or selector_col.commitment is None:
        raise ValueError("failed to build selector column")
    return tuple(selector_col.evals), tuple(selector_col.coeffs), selector_col.commitment


def _selector_column(params: RingProofParams) -> Column:
    evals, coeffs, commitment = _selector_column_data(
        params.domain_size,
        params.max_ring_size,
        params.omega,
        params.prime,
        params.pcs,
    )
    return Column("s", list(evals), list(coeffs), commitment=commitment.dup(), size=params.domain_size)


@dataclass
class RingRoot:
    px: Column
    py: Column
    s: Column
    params: RingProofParams | None = None

    @classmethod
    def from_ring(cls, ring: Ring, params: RingProofParams | None = None):
        if params is None:
            params = ring.params
        px = [point[0] for point in ring.nm_points]
        py = [point[1] for point in ring.nm_points]
        px_col = Column("Px", px, size=params.domain_size)
        py_col = Column("Py", py, size=params.domain_size)
        s_col = _selector_column(params)
        for col in (px_col, py_col):
            col.interpolate(params.omega, params.prime)
            col.commit(params.pcs)
        return cls(px=px_col, py=py_col, s=s_col, params=params)

    def fixed_commitments(self, params: RingProofParams | None = None) -> list[Any]:
        """Return fixed-column commitments for the ring root."""
        if params is None:
            params = self.params
        if params is None:
            raise ValueError("Ring root commitments require ring proof parameters")

        return [
            require_commitment(self.px),
            require_commitment(self.py),
            require_commitment(self.s),
        ]

    def verifier_transcript_prefix(self, params: RingProofParams | None = None, transcript_challenge: bytes | None = None):
        """Return a transcript state after absorbing the fixed verifier key."""
        if params is None:
            params = self.params
        if params is None:
            raise ValueError("Ring root verifier transcript requires ring proof parameters")

        commitments = self.fixed_commitments(params)
        commitment_bytes = [params.pcs.serialize_g1_uncompressed(commitment) for commitment in commitments]
        verifier_key_bytes = serialize_verifier_key(
            params.pcs.srs.g1_points[0],
            [(b, a) for pair in params.pcs.srs.g2_points for point in pair for a, b in [point]],
            commitment_bytes,
        )
        if transcript_challenge is None:
            transcript_challenge = params.cv.curve.params.suite_id

        transcript = FiatShamirTranscript(params.prime, transcript_challenge)
        transcript.absorb_labeled(b"vk", verifier_key_bytes)
        return transcript

    @staticmethod
    def encoded_len(params: RingProofParams | None = None) -> int:
        commitment_size = params.pcs.commitment_size if params is not None else KZG.commitment_size
        return 3 * commitment_size

    def encode(self) -> bytes:
        pcs = self.params.pcs if self.params is not None else KZG
        return b"".join(
            (
                pcs.compress_g1(require_commitment(self.px)),
                pcs.compress_g1(require_commitment(self.py)),
                pcs.compress_g1(require_commitment(self.s)),
            )
        )

    @classmethod
    def decode(cls, data: bytes, params: RingProofParams | None = None) -> "RingRoot":
        commitment_size = params.pcs.commitment_size if params is not None else KZG.commitment_size
        expected = cls.encoded_len(params)
        if len(data) != expected:
            raise ValueError(f"invalid ring root length: ring root must be exactly {expected} bytes, got {len(data)}")

        pcs = params.pcs if params is not None else KZG
        reader = _RingRootReader(data, commitment_size)
        px_commitment = reader.g1(pcs)
        py_commitment = reader.g1(pcs)
        s_commitment = reader.g1(pcs)
        reader.finish()

        if params is None:
            px = Column("px", [], commitment=px_commitment)
            py = Column("py", [], commitment=py_commitment)
            s = Column("s", [], commitment=s_commitment)
        else:
            px = Column("px", [], commitment=px_commitment, size=params.domain_size)
            py = Column("py", [], commitment=py_commitment, size=params.domain_size)
            s = Column("s", [], commitment=s_commitment, size=params.domain_size)

        return cls(px=px, py=py, s=s, params=params)

    def matches_ring(self, ring: Ring) -> bool:
        params = ring.params
        domain_size = params.domain_size
        if len(self.px.evals) >= domain_size and len(self.py.evals) >= domain_size and len(self.s.evals) >= domain_size:
            return (
                tuple(self.px.evals[:domain_size]) == tuple(point[0] for point in ring.nm_points)
                and tuple(self.py.evals[:domain_size]) == tuple(point[1] for point in ring.nm_points)
                and tuple(self.s.evals[:domain_size]) == tuple(1 if i < params.max_ring_size else 0 for i in range(domain_size))
            )
        return RingRoot.from_ring(ring, params).encode() == self.encode()


class _RingRootReader:
    def __init__(self, data: bytes, commitment_size: int) -> None:
        self.data = data
        self.commitment_size = commitment_size
        self.offset = 0

    def g1(self, pcs: Any) -> Any:
        end = self.offset + self.commitment_size
        commitment = pcs.decompress_g1(self.data[self.offset : end])
        self.offset = end
        return commitment

    def finish(self) -> None:
        if self.offset != len(self.data):
            raise ValueError(f"trailing bytes in ring root: {len(self.data) - self.offset}")
