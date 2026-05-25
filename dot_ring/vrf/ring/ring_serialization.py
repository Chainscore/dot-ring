from __future__ import annotations

from typing import Any, cast

from dot_ring.ring_proof.helpers import Helpers as H
from dot_ring.ring_proof.params import RingProofParams
from dot_ring.ring_proof.pcs.protocol import G1Commitment

RING_SCALAR_LEN = 32


def ring_proof_len(params: RingProofParams) -> int:
    return 7 * params.pcs.commitment_size + 8 * RING_SCALAR_LEN


def compress_g1(params: RingProofParams, point: G1Commitment) -> bytes:
    if hasattr(params.pcs, "compress_g1"):
        return params.pcs.compress_g1(point)
    return bytes.fromhex(H.bls_g1_compress(cast(tuple, point)))


def decompress_g1(params: RingProofParams, data: bytes) -> G1Commitment:
    if hasattr(params.pcs, "decompress_g1"):
        return params.pcs.decompress_g1(data)
    return H.bls_g1_decompress(data.hex())


def transcript_g1(params: RingProofParams, point: G1Commitment) -> Any:
    if params.pcs.commitment_size == 32:
        return params.pcs.serialize_g1_uncompressed(point)
    return params.pcs.normalize_g1(point)


def transcript_vk(params: RingProofParams, commitments: list[G1Commitment]) -> dict[str, Any]:
    if params.pcs.commitment_size == 32:
        return {
            "g1": params.pcs.srs.g1_uncompressed[0],
            "g2": params.pcs.srs.g2_uncompressed,
            "commitments": [transcript_g1(params, commitment) for commitment in commitments],
        }
    return {
        "g1": params.pcs.srs.g1_points[0],
        "g2": H.altered_points(params.pcs.srs.g2_points),
        "commitments": [params.pcs.normalize_g1(commitment) for commitment in commitments],
    }
