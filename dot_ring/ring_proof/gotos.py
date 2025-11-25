from typing import List, Any
from dot_ring.ring_proof.curve.bandersnatch import TwistedEdwardCurve
from dot_ring.ring_proof.columns.columns import PublicColumnBuilder as PC
from dot_ring.ring_proof.pcs.srs import srs
from dot_ring.ring_proof.transcript.phases import phase1_alphas, phase3_nu_vector
from dot_ring.ring_proof.transcript.transcript import Transcript
from dot_ring.ring_proof.constants import (
    Blinding_Base,
    S_PRIME,
    OMEGA_2048,
    SeedPoint,
    PaddingPoint,
)
from dot_ring.ring_proof.columns.columns import (
    WitnessColumnBuilder,
)
from dot_ring.ring_proof.constraints.constraints import RingConstraintBuilder
from dot_ring.ring_proof.helpers import Helpers as H, Helpers
from dot_ring.vrf.ring.ring_vrf import RingRoot
from dot_ring.ring_proof.constraints.aggregation import aggregate_constraints
from dot_ring.ring_proof.proof.quotient_poly import QuotientPoly
from dot_ring.ring_proof.proof.linearization_poly import LAggPoly
from dot_ring.ring_proof.proof.aggregation_poly import AggPoly
from dot_ring.ring_proof.verify import Verify
from dot_ring.ring_proof.constants import D_512 as D
from dot_ring.curve.specs.bandersnatch import (
    Bandersnatch_TE_Curve,
    BandersnatchPoint,
)
from dot_ring.vrf.pedersen.pedersen import PedersenVRF

def verify_signature(
    message: bytes | str, ring_root: bytes | str, proof: bytes | str
) -> bool:
    """
    get the bls signature, other params if needed and verify it
    """
    # is_valid=func() # make the func call or logic u want
    # return is_valid
    if not isinstance(proof, bytes):
        proof = bytes.fromhex(proof)

    proof_ptr = [
        H.bls_g1_decompress(proof[:48]),
        H.bls_g1_decompress(proof[48 * 1 : 48 * 2]),
        H.bls_g1_decompress(proof[48 * 2 : 48 * 3]),
        H.bls_g1_decompress(proof[48 * 3 : 48 * 4]),
        H.to_scalar_int(proof[48 * 4 + (0 * 32) : 48 * 4 + (1 * 32)]),
        H.to_scalar_int(proof[48 * 4 + (1 * 32) : 48 * 4 + (2 * 32)]),
        H.to_scalar_int(proof[48 * 4 + (2 * 32) : 48 * 4 + (3 * 32)]),
        H.to_scalar_int(proof[48 * 4 + (3 * 32) : 48 * 4 + (4 * 32)]),
        H.to_scalar_int(proof[48 * 4 + (4 * 32) : 48 * 4 + (5 * 32)]),
        H.to_scalar_int(proof[48 * 4 + (5 * 32) : 48 * 4 + (6 * 32)]),
        H.to_scalar_int(proof[48 * 4 + (6 * 32) : 48 * 4 + (7 * 32)]),
        H.bls_g1_decompress(proof[48 * 4 + (7 * 32) : (48 * 4) + (7 * 32) + 48]),
        H.to_scalar_int(proof[(48 * 4) + (7 * 32) + 48 : 48 * 4 + (7 * 32) + 48 + 32]),
        H.bls_g1_decompress(proof[48 * 4 + (7 * 32) + 48 + 32 : -48]),
        H.bls_g1_decompress(proof[-48:]),
    ]

    if not isinstance(ring_root, bytes):
        ring_root = bytes.fromhex(ring_root)

    rltn_to_proove = BandersnatchPoint.string_to_point(message)  # relation to proove
    rltn = (rltn_to_proove.x, rltn_to_proove.y)
    res_plus_seed = TwistedEdwardCurve.add(SeedPoint, rltn)
    C_px, C_py, C_s = (
        H.bls_g1_decompress(ring_root[:48]),
        H.bls_g1_decompress(ring_root[48:-48]),
        H.bls_g1_decompress(ring_root[-48:]),
    )
    fixed_cols_cmts = [C_px, C_py, C_s]
    verifier_key = {
        "g1": srs.g1_points[0],
        "g2": H.altered_points(srs.g2_points),
        "commitments": [
            H.to_int(each) for each in H.bls_projective_2_affine(fixed_cols_cmts)
        ],
    }
    valid = Verify(
        proof_ptr, verifier_key, fixed_cols_cmts, rltn, res_plus_seed, SeedPoint, D
    )
    return valid.is_signtaure_valid()


def pedersen_proof_to_hash(pedersen_proof: bytes | str) -> bytes:
    """get the pedersen proof alone and return the 32 bytes hash"""
    if not isinstance(pedersen_proof, bytes):
        pedersen_proof = bytes.fromhex(pedersen_proof)

    if int.from_bytes(pedersen_proof[:32], "little") == 0:
        # return ByteArray32(pedersen_proof[:32])
        return pedersen_proof[:32]

    vrf = PedersenVRF(Bandersnatch_TE_Curve, BandersnatchPoint)
    # extract the fist 32 bytes as it's the gamma
    gamma = BandersnatchPoint.string_to_point(pedersen_proof[:32])
    p_2h = vrf.proof_to_hash(gamma)
    return p_2h[:32]