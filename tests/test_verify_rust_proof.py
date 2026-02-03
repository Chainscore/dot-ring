import json
import sys
from pathlib import Path

import pytest

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from dot_ring.ring_proof.verify import Verify
from dot_ring.ring_proof.constants import D_512, D_2048, OMEGA_2048, S_PRIME
from dot_ring.ring_proof.curve.bandersnatch import TwistedEdwardCurve
from dot_ring.ring_proof.pcs import srs
from dot_ring import blst

# Import serialization utilities
from tests.utils.arkworks_serde import (
    deserialize_fq_field_element,
    deserialize_bandersnatch_point,
    deserialize_bls12_381_g1,
    compressed_g1_to_uncompressed_bytes,
    compressed_g2_to_uncompressed_bytes,
)


def load_test_parameters() -> dict:
    """
    Load deterministic test parameters from JSON file.

    These parameters were extracted once from Rust's test_rng() and saved
    for deterministic test execution without needing to rebuild Rust code.

    Returns:
        Dictionary with h, seed, result, domain_size, etc.
    """
    params_file = Path(__file__).parent / "vectors" / "others" / "test_parameters.json"
    with open(params_file, 'r') as f:
        return json.load(f)


def parse_proof_from_json(proof_json: dict) -> tuple:
    """
    Parse proof from Rust-generated JSON.

    Returns (proof_tuple, raw_bytes_dict) where:
    - proof_tuple: deserialized proof compatible with Python Verify class
    - raw_bytes_dict: raw arkworks-serialized bytes for transcript
    """
    proof = proof_json["proof"]

    # Parse column commitments (4 × 48-byte G1 points)
    col_cmts_hex = proof["column_commitments"]
    col_cmts_bytes = bytes.fromhex(col_cmts_hex)

    c_b = deserialize_bls12_381_g1(col_cmts_bytes[0:48])
    c_accip = deserialize_bls12_381_g1(col_cmts_bytes[48:96])
    c_accx = deserialize_bls12_381_g1(col_cmts_bytes[96:144])
    c_accy = deserialize_bls12_381_g1(col_cmts_bytes[144:192])

    # Parse evaluations at zeta (7 × 32-byte Fq field elements)
    cols_at_zeta_hex = proof["columns_at_zeta"]
    cols_at_zeta_bytes = bytes.fromhex(cols_at_zeta_hex)

    px_zeta = deserialize_fq_field_element(cols_at_zeta_bytes[0:32])
    py_zeta = deserialize_fq_field_element(cols_at_zeta_bytes[32:64])
    s_zeta = deserialize_fq_field_element(cols_at_zeta_bytes[64:96])
    b_zeta = deserialize_fq_field_element(cols_at_zeta_bytes[96:128])
    accip_zeta = deserialize_fq_field_element(cols_at_zeta_bytes[128:160])
    accx_zeta = deserialize_fq_field_element(cols_at_zeta_bytes[160:192])
    accy_zeta = deserialize_fq_field_element(cols_at_zeta_bytes[192:224])

    # Parse other proof components
    cq_bytes = bytes.fromhex(proof["quotient_commitment"])
    c_q = deserialize_bls12_381_g1(cq_bytes)
    l_zeta_omega = deserialize_fq_field_element(bytes.fromhex(proof["lin_at_zeta_omega"]))

    # KZG opening proofs (48-byte G1 points)
    phi_zeta = deserialize_bls12_381_g1(bytes.fromhex(proof["agg_at_zeta_proof"]))
    phi_zeta_omega = deserialize_bls12_381_g1(bytes.fromhex(proof["lin_at_zeta_omega_proof"]))

    proof_tuple = (
        c_b, c_accip, c_accx, c_accy,
        px_zeta, py_zeta, s_zeta, b_zeta,
        accip_zeta, accx_zeta, accy_zeta,
        c_q, l_zeta_omega, phi_zeta, phi_zeta_omega
    )

    # Store raw bytes for transcript (matching arkworks serialization)
    raw_bytes = {
        "col_commitments": [
            col_cmts_bytes[0:48],
            col_cmts_bytes[48:96],
            col_cmts_bytes[96:144],
            col_cmts_bytes[144:192],
        ],
        "quotient_commitment": cq_bytes,
    }

    return (proof_tuple, raw_bytes)


def parse_verifier_key(vk_json: dict, use_global_srs: bool = True) -> dict:
    """
    Parse verifier key from JSON.

    VerifierKey serialization order (384 bytes):
    1. pcs_raw_vk (RawKzgVerifierKey, 240 bytes):
        - g1: 48 bytes G1
        - g2: 96 bytes G2
        - tau_g2: 96 bytes G2
    2. fixed_columns_committed (FixedColumnsCommitted, 144 bytes):
        - points[0]: C_px (48 bytes G1)
        - points[1]: C_py (48 bytes G1)
        - ring_selector: C_s (48 bytes G1)

    If use_global_srs is True, uses the global SRS instead of parsing G1/G2 from vk.
    """
    vk_hex = vk_json["verifier_key"]["verification_key"]
    vk_bytes = bytes.fromhex(vk_hex)

    # Fixed columns commitments (offsets 240-384)
    c_px = deserialize_bls12_381_g1(vk_bytes[240:288])
    c_py = deserialize_bls12_381_g1(vk_bytes[288:336])
    c_s = deserialize_bls12_381_g1(vk_bytes[336:384])

    # Convert to format expected by Python verifier
    from dot_ring.ring_proof.helpers import Helpers as H
    from py_ecc.optimized_bls12_381 import normalize as nm

    if use_global_srs:
        # Use the global SRS which has already been updated with Rust values
        g1_int = H.to_int(srs.srs.g1_points[0])
        g2_altered = H.altered_points(srs.srs.g2_points)
    else:
        # Parse from verifier key bytes
        kzg_g1 = deserialize_bls12_381_g1(vk_bytes[0:48])
        g1_normalized = nm(kzg_g1)
        g1_int = H.to_int(g1_normalized)

        # G2 parsing would go here but is complex
        # For now, fall back to using global SRS
        g2_altered = H.altered_points(srs.srs.g2_points)

    # Create verifier_key dict in the format expected by Verify class
    verifier_key_dict = {
        "g1": g1_int,
        "g2": g2_altered,
        "commitments": [H.to_int(nm(c_px)), H.to_int(nm(c_py)), H.to_int(nm(c_s))]
    }

    return {
        "fixed_cols": [c_px, c_py, c_s],
        "verifier_key": verifier_key_dict
    }


@pytest.fixture(scope="module")
def rust_parameters():
    """Load deterministic test parameters from JSON."""
    return load_test_parameters()


@pytest.fixture(scope="module")
def proof_data():
    """Load Rust-generated proof."""
    proof_path = Path(__file__).parent / "vectors" / "others" / "ring_proof_rust_generated.json"
    with open(proof_path) as f:
        return json.load(f)


def test_verify_rust_generated_proof(rust_parameters, proof_data):
    """
    Test verification of Rust-generated ring proof.

    This test demonstrates that the Python verifier can verify
    proofs generated by the Rust reference implementation.
    """
    params = rust_parameters

    # Extract and update SRS from verifier key
    vk_compressed = bytes.fromhex(proof_data["verifier_key"]["verification_key"])
    g1_0_bytes = vk_compressed[0:48]
    g2_0_bytes = vk_compressed[48:144]
    g2_1_bytes = vk_compressed[144:240]

    g1_0_blst = blst.P1(blst.P1_Affine(g1_0_bytes))
    g2_0_blst = blst.P2(blst.P2_Affine(g2_0_bytes))
    g2_1_blst = blst.P2(blst.P2_Affine(g2_1_bytes))

    original_g1 = srs.srs.blst_g1
    original_g2 = srs.srs.blst_g2

    srs.srs.blst_g1 = [g1_0_blst] + list(original_g1[1:])
    srs.srs.blst_g2 = [g2_0_blst, g2_1_blst] + list(original_g2[2:])

    # Compute domain based on size
    domain_size = params["domain_size"]
    if domain_size == 512:
        domain = D_512
    elif domain_size == 1024:
        omega_1024 = pow(OMEGA_2048, 2048 // 1024, S_PRIME)
        domain = [pow(omega_1024, i, S_PRIME) for i in range(1024)]
    elif domain_size == 2048:
        domain = D_2048
    else:
        raise ValueError(f"Unsupported domain size: {domain_size}")

    # Deserialize Bandersnatch points
    seed_x_bytes = bytes.fromhex(params["seed"]["x"])
    seed_y_bytes = bytes.fromhex(params["seed"]["y"])
    seed_point = deserialize_bandersnatch_point(seed_x_bytes, seed_y_bytes)

    result_x_bytes = bytes.fromhex(params["result"]["x"])
    result_y_bytes = bytes.fromhex(params["result"]["y"])
    result_point = deserialize_bandersnatch_point(result_x_bytes, result_y_bytes)

    result_ark_bytes = result_x_bytes + result_y_bytes
    result_plus_seed = TwistedEdwardCurve.add(result_point, seed_point)

    # Parse proof and verifier key
    proof_tuple, raw_bytes = parse_proof_from_json(proof_data)
    vk_dict = parse_verifier_key(proof_data)

    # Prepare raw bytes for transcript
    vk_uncompressed = (
        compressed_g1_to_uncompressed_bytes(vk_compressed[0:48]) +
        compressed_g2_to_uncompressed_bytes(vk_compressed[48:144]) +
        compressed_g2_to_uncompressed_bytes(vk_compressed[144:240]) +
        compressed_g1_to_uncompressed_bytes(vk_compressed[240:288]) +
        compressed_g1_to_uncompressed_bytes(vk_compressed[288:336]) +
        compressed_g1_to_uncompressed_bytes(vk_compressed[336:384])
    )

    quotient_compressed = bytes.fromhex(proof_data["proof"]["quotient_commitment"])
    quotient_uncompressed = compressed_g1_to_uncompressed_bytes(quotient_compressed)
    raw_bytes["quotient_commitment_uncompressed"] = quotient_uncompressed

    # Create verifier and verify
    verifier = Verify(
        proof=proof_tuple,
        vk=vk_uncompressed,
        fixed_cols=vk_dict["fixed_cols"],
        rl_to_proove=result_ark_bytes,
        rps=result_plus_seed,
        seed_point=seed_point,
        Domain=domain,
        raw_proof_bytes=raw_bytes,
        transcript_challenge=b"w3f-ring-proof-test"
    )

    # Verify proof
    assert verifier.is_valid(), "Proof verification failed!"