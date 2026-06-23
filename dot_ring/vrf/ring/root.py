from dataclasses import dataclass
from functools import lru_cache
from typing import Any

from dot_ring.ring_proof.columns.columns import Column
from dot_ring.ring_proof.params import RingProofParams
from dot_ring.ring_proof.pcs.kzg import KZG
from dot_ring.ring_proof.transcript.phases import serialize_verifier_key
from dot_ring.ring_proof.transcript.transcript import FiatShamirTranscript
from dot_ring.vrf.ring.members import Ring


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

        s_evals, s_coeffs, s_commitment = _selector_column_data(
            domain_size=params.domain_size,
            max_ring_size=params.max_ring_size,
            omega=params.omega,
            prime=params.prime,
            pcs=params.pcs,
        )
        s = Column("s", list(s_evals), coeffs=list(s_coeffs), _commitment=s_commitment, size=params.domain_size)

        px_evals, px_coeffs, px_commitment, py_evals, py_coeffs, py_commitment = _public_keys_column_data(
            nm_points=ring.nm_points,
            domain_size=params.domain_size,
            omega=params.omega,
            prime=params.prime,
            pcs=params.pcs,
        )
        px = Column("px", list(px_evals), coeffs=list(px_coeffs), _commitment=px_commitment, size=params.domain_size)
        py = Column("py", list(py_evals), coeffs=list(py_coeffs), _commitment=py_commitment, size=params.domain_size)

        return cls(px=px, py=py, s=s, params=params)

    def fixed_commitments(self) -> list[Any]:
        """Return fixed-column commitments for the ring root."""
        return [
            self.px.commitment,
            self.py.commitment,
            self.s.commitment,
        ]

    def verifier_transcript_prefix(self, transcript_challenge: bytes | None = None):
        """Return a transcript state after absorbing the fixed verifier key."""
        if self.params is None:
            raise ValueError("Ring root verifier transcript requires ring proof parameters")

        commitments = self.fixed_commitments()
        commitment_bytes = [self.params.pcs.serialize_g1_uncompressed(commitment) for commitment in commitments]
        verifier_key_bytes = serialize_verifier_key(
            self.params.pcs.srs.g1_points[0],
            [(b, a) for pair in self.params.pcs.srs.g2_points for point in pair for a, b in [point]],
            commitment_bytes,
        )
        if transcript_challenge is None:
            transcript_challenge = self.params.cv.curve.params.suite_id

        transcript = FiatShamirTranscript(self.params.prime, transcript_challenge)
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
                pcs.compress_g1(self.px.commitment),
                pcs.compress_g1(self.py.commitment),
                pcs.compress_g1(self.s.commitment),
            )
        )

    @classmethod
    def decode(cls, data: bytes, ring: Ring | RingProofParams | None = None) -> "RingRoot":
        params = ring.params if isinstance(ring, Ring) else ring
        if params is None:
            params = RingProofParams()
        commitment_size = params.pcs.commitment_size
        expected = cls.encoded_len(params)
        if len(data) != expected:
            raise ValueError(f"invalid ring root length: ring root must be exactly {expected} bytes, got {len(data)}")

        pcs = params.pcs
        reader = _RingRootReader(data, commitment_size)
        px_commitment = reader.g1(pcs)
        py_commitment = reader.g1(pcs)
        s_commitment = reader.g1(pcs)
        reader.finish()

        px = Column("px", [], _commitment=px_commitment, size=params.domain_size)
        py = Column("py", [], _commitment=py_commitment, size=params.domain_size)
        s = Column("s", [], _commitment=s_commitment, size=params.domain_size)

        return cls(px=px, py=py, s=s, params=params)

    def matches_ring(self, ring: Ring) -> bool:
        return RingRoot.from_ring(ring).encode() == self.encode()


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


# Assumption: Selector column would likely be same as long as ring size doesn't change
@lru_cache(maxsize=2)
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


# Assumption: Ring changes are infrequent, so caching the ring for a given set of keys is reasonable
@lru_cache(maxsize=8)
def _public_keys_column_data(
    nm_points: tuple[tuple[int, int], ...],
    domain_size: int,
    omega: int,
    prime: int,
    pcs: Any,
) -> tuple[tuple[int, ...], tuple[int, ...], Any, tuple[int, ...], tuple[int, ...], Any]:
    px_col = Column("Px", [point[0] for point in nm_points], size=domain_size)
    py_col = Column("Py", [point[1] for point in nm_points], size=domain_size)
    for col in (px_col, py_col):
        col.interpolate(omega, prime)
        col.commit(pcs)
        if col.coeffs is None or col.commitment is None:
            raise ValueError(f"failed to build {col.name} column")
    return (
        tuple(px_col.evals),
        tuple(px_col.coeffs),
        px_col.commitment,
        tuple(py_col.evals),
        tuple(py_col.coeffs),
        py_col.commitment,
    )
