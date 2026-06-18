from dataclasses import dataclass
from functools import lru_cache
from typing import Any, cast

from dot_ring.ring_proof.columns.columns import Column, require_commitment
from dot_ring.ring_proof.helpers import Helpers as H
from dot_ring.ring_proof.params import RingProofParams
from dot_ring.ring_proof.pcs.kzg import KZG
from dot_ring.ring_proof.pcs.utils import pcs_compress_g1, pcs_decompress_g1, pcs_transcript_g1

from .members import Ring


def _pcs_cache_token(pcs: Any) -> tuple[int, int, int | None]:
    pcs_srs = getattr(pcs, "srs", None)
    return (
        id(pcs_srs),
        id(getattr(pcs_srs, "blst_g1_memory", None)),
        getattr(pcs, "commitment_size", None),
    )


# Global bounded cache: selector columns are fixed for a params/PCS tuple.
@lru_cache(maxsize=16)
def _selector_column_data(
    domain_size: int,
    max_ring_size: int,
    omega: int,
    prime: int,
    pcs: Any,
    _pcs_token: tuple[int, int, int | None],
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
        _pcs_cache_token(params.pcs),
    )
    return Column("s", list(evals), list(coeffs), commitment=_copy_commitment(commitment), size=params.domain_size)


def _copy_commitment(commitment: Any) -> Any:
    return commitment.dup() if hasattr(commitment, "dup") else commitment


def _decompressed_root_commitments(
    data: bytes,
    commitment_size: int,
    pcs: Any,
) -> tuple[Any, Any, Any]:
    expected = 3 * commitment_size
    if len(data) != expected:
        raise ValueError(f"invalid ring root length: ring root must be exactly {expected} bytes, got {len(data)}")
    return (
        pcs_decompress_g1(pcs, data[0:commitment_size]),
        pcs_decompress_g1(pcs, data[commitment_size : commitment_size * 2]),
        pcs_decompress_g1(pcs, data[commitment_size * 2 : expected]),
    )


def _ring_selector(params: RingProofParams) -> tuple[int, ...]:
    return tuple(1 if i < params.max_ring_size else 0 for i in range(params.domain_size))


def _verifier_key_transcript_data(params: RingProofParams, commitments: list[Any]) -> dict[str, Any]:
    return {
        "g1": params.pcs.srs.g1_points[0],
        "g2": H.altered_points(params.pcs.srs.g2_points),
        "commitments": [pcs_transcript_g1(params.pcs, commitment) for commitment in commitments],
    }


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
        # Px, Py, s points
        px, py = H.unzip(ring.nm_points)
        # Columns
        px_col = Column("Px", px, size=params.domain_size)
        py_col = Column("Py", py, size=params.domain_size)
        s_col = _selector_column(params)
        for col in (px_col, py_col):
            col.interpolate(params.omega, params.prime)
            col.commit(params.pcs)
        return cls(px=px_col, py=py_col, s=s_col, params=params)

    def verifier_key(self, params: RingProofParams | None = None) -> tuple[list[Any], dict[str, Any]]:
        """Return fixed-column commitments and their transcript verifier key."""
        if params is None:
            params = self.params
        if params is None:
            raise ValueError("Ring root verifier key requires ring proof parameters")

        commitments = [
            require_commitment(self.px),
            require_commitment(self.py),
            require_commitment(self.s),
        ]

        verifier_key = _verifier_key_transcript_data(params, commitments)
        return commitments, verifier_key

    def verifier_transcript_prefix(self, params: RingProofParams | None = None, transcript_challenge: bytes | None = None):
        """Return a transcript state after absorbing the fixed verifier key."""
        if params is None:
            params = self.params
        if params is None:
            raise ValueError("Ring root verifier transcript requires ring proof parameters")

        _, verifier_key = self.verifier_key(params)
        if transcript_challenge is None:
            transcript_challenge = params.cv.curve.params.suite_id

        from dot_ring.ring_proof.transcript.serialize import serialize
        from dot_ring.ring_proof.transcript.transcript import FiatShamirTranscript

        transcript = FiatShamirTranscript(params.prime, transcript_challenge)
        # Verifier-key transcript prefix is reused before proof-local data is absorbed.
        transcript.add_serialized(b"vk", serialize(verifier_key))
        return transcript

    def to_bytes(self) -> bytes:
        pcs = self.params.pcs if self.params is not None else None
        if pcs is not None:
            return b"".join(
                (
                    pcs_compress_g1(pcs, require_commitment(self.px)),
                    pcs_compress_g1(pcs, require_commitment(self.py)),
                    pcs_compress_g1(pcs, require_commitment(self.s)),
                )
            )
        for col in (self.px, self.py, self.s):
            if col.commitment is None:
                raise ValueError("Ring root is missing commitments")
        comm_keys = (
            H.bls_g1_compress(cast(Any, require_commitment(self.px))),
            H.bls_g1_compress(cast(Any, require_commitment(self.py))),
            H.bls_g1_compress(cast(Any, require_commitment(self.s))),
        )
        return bytes.fromhex(comm_keys[0]) + bytes.fromhex(comm_keys[1]) + bytes.fromhex(comm_keys[2])

    @classmethod
    def from_bytes(cls, data: bytes, params: RingProofParams | None = None) -> "RingRoot":
        if params is not None:
            commitment_size = params.pcs.commitment_size
        else:
            commitment_size = KZG.commitment_size
        expected = 3 * commitment_size
        if len(data) != expected:
            raise ValueError(f"invalid ring root length: ring root must be exactly {expected} bytes, got {len(data)}")

        pcs = params.pcs if params is not None else KZG
        px_commitment, py_commitment, s_commitment = _decompressed_root_commitments(
            bytes(data),
            commitment_size,
            pcs,
        )

        px = Column(name="px", evals=[], commitment=_copy_commitment(px_commitment))
        py = Column(name="py", evals=[], commitment=_copy_commitment(py_commitment))
        s = Column(name="s", evals=[], commitment=_copy_commitment(s_commitment))

        return cls(px=px, py=py, s=s, params=params)

    def matches_ring(self, ring: Ring) -> bool:
        params = ring.params
        domain_size = params.domain_size
        if (
            len(self.px.evals) >= domain_size
            and len(self.py.evals) >= domain_size
            and len(self.s.evals) >= domain_size
        ):
            return (
                tuple(self.px.evals[:domain_size]) == tuple(point[0] for point in ring.nm_points)
                and tuple(self.py.evals[:domain_size]) == tuple(point[1] for point in ring.nm_points)
                and tuple(self.s.evals[:domain_size]) == _ring_selector(params)
            )
        return RingRoot.from_ring(ring, params).to_bytes() == self.to_bytes()
