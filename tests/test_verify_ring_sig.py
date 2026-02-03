import json
import sys
from pathlib import Path

import pytest

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from dot_ring import blst
from dot_ring.ring_proof.constants import EVAL_DOMAINS
from dot_ring.ring_proof.curve.bandersnatch import TwistedEdwardCurve
from dot_ring.ring_proof.pcs import srs
from dot_ring.ring_proof.pcs.utils import g2_to_blst
from dot_ring.ring_proof.verify import Verify
from tests.utils.arkworks_serde import (
    compressed_g1_to_uncompressed_bytes,
    compressed_g2_to_uncompressed_bytes,
    deserialize_bandersnatch_point,
    deserialize_bls12_381_g1,
    deserialize_bls12_381_g2,
    deserialize_fq_field_element,
)


def parse_proof_from_json(proof_json: dict) -> tuple:
    proof = proof_json["proof"]

    col_cmts_bytes = bytes.fromhex(proof["column_commitments"])
    c_b = deserialize_bls12_381_g1(col_cmts_bytes[0:48])
    c_accip = deserialize_bls12_381_g1(col_cmts_bytes[48:96])
    c_accx = deserialize_bls12_381_g1(col_cmts_bytes[96:144])
    c_accy = deserialize_bls12_381_g1(col_cmts_bytes[144:192])

    cols_at_zeta_bytes = bytes.fromhex(proof["columns_at_zeta"])
    px_zeta = deserialize_fq_field_element(cols_at_zeta_bytes[0:32])
    py_zeta = deserialize_fq_field_element(cols_at_zeta_bytes[32:64])
    s_zeta = deserialize_fq_field_element(cols_at_zeta_bytes[64:96])
    b_zeta = deserialize_fq_field_element(cols_at_zeta_bytes[96:128])
    accip_zeta = deserialize_fq_field_element(cols_at_zeta_bytes[128:160])
    accx_zeta = deserialize_fq_field_element(cols_at_zeta_bytes[160:192])
    accy_zeta = deserialize_fq_field_element(cols_at_zeta_bytes[192:224])

    cq_bytes = bytes.fromhex(proof["quotient_commitment"])
    c_q = deserialize_bls12_381_g1(cq_bytes)
    l_zeta_omega = deserialize_fq_field_element(bytes.fromhex(proof["lin_at_zeta_omega"]))

    phi_zeta = deserialize_bls12_381_g1(bytes.fromhex(proof["agg_at_zeta_proof"]))
    phi_zeta_omega = deserialize_bls12_381_g1(bytes.fromhex(proof["lin_at_zeta_omega_proof"]))

    proof_tuple = (
        c_b,
        c_accip,
        c_accx,
        c_accy,
        px_zeta,
        py_zeta,
        s_zeta,
        b_zeta,
        accip_zeta,
        accx_zeta,
        accy_zeta,
        c_q,
        l_zeta_omega,
        phi_zeta,
        phi_zeta_omega,
    )

    raw_bytes = {
        "col_commitments": [
            col_cmts_bytes[0:48],
            col_cmts_bytes[48:96],
            col_cmts_bytes[96:144],
            col_cmts_bytes[144:192],
        ],
        "quotient_commitment": cq_bytes,
    }

    return proof_tuple, raw_bytes


def parse_verifier_key(vk_hex: str) -> tuple[bytes, list]:
    vk_bytes = bytes.fromhex(vk_hex)

    c_px = deserialize_bls12_381_g1(vk_bytes[240:288])
    c_py = deserialize_bls12_381_g1(vk_bytes[288:336])
    c_s = deserialize_bls12_381_g1(vk_bytes[336:384])

    return vk_bytes, [c_px, c_py, c_s]


def verify_vector(vector_path: Path) -> None:
    with open(vector_path) as f:
        proof_data = json.load(f)

    params = proof_data["metadata"]["parameters"]
    domain = EVAL_DOMAINS[params["domain_size"]]
    padding_rows = params.get("padding_rows", 4)

    seed_x_bytes = bytes.fromhex(params["seed"]["x"])
    seed_y_bytes = bytes.fromhex(params["seed"]["y"])
    seed_point = deserialize_bandersnatch_point(seed_x_bytes, seed_y_bytes)

    result_x_bytes = bytes.fromhex(params["result"]["x"])
    result_y_bytes = bytes.fromhex(params["result"]["y"])
    result_point = deserialize_bandersnatch_point(result_x_bytes, result_y_bytes)

    result_ark_bytes = result_x_bytes + result_y_bytes
    result_plus_seed = TwistedEdwardCurve.add(result_point, seed_point)

    proof_tuple, raw_bytes = parse_proof_from_json(proof_data)
    vk_bytes, fixed_cols = parse_verifier_key(proof_data["verifier_key"]["verification_key"])

    # Update SRS from verifier key
    g1_0_bytes = vk_bytes[0:48]
    g2_0_bytes = vk_bytes[48:144]
    g2_1_bytes = vk_bytes[144:240]

    g1_0_blst = blst.P1(blst.P1_Affine(g1_0_bytes))
    g2_0_affine = deserialize_bls12_381_g2(g2_0_bytes)
    g2_1_affine = deserialize_bls12_381_g2(g2_1_bytes)
    g2_0_blst = g2_to_blst(g2_0_affine)
    g2_1_blst = g2_to_blst(g2_1_affine)

    original_g1 = srs.srs.blst_g1
    original_g2 = srs.srs.blst_g2
    srs.srs.blst_g1 = [g1_0_blst] + list(original_g1[1:])
    srs.srs.blst_g2 = [g2_0_blst, g2_1_blst] + list(original_g2[2:])

    vk_uncompressed = (
        compressed_g1_to_uncompressed_bytes(vk_bytes[0:48])
        + compressed_g2_to_uncompressed_bytes(vk_bytes[48:144])
        + compressed_g2_to_uncompressed_bytes(vk_bytes[144:240])
        + compressed_g1_to_uncompressed_bytes(vk_bytes[240:288])
        + compressed_g1_to_uncompressed_bytes(vk_bytes[288:336])
        + compressed_g1_to_uncompressed_bytes(vk_bytes[336:384])
    )

    quotient_compressed = bytes.fromhex(proof_data["proof"]["quotient_commitment"])
    quotient_uncompressed = compressed_g1_to_uncompressed_bytes(quotient_compressed)
    raw_bytes["quotient_commitment_uncompressed"] = quotient_uncompressed

    verifier = Verify(
        proof=proof_tuple,
        vk=vk_uncompressed,
        fixed_cols=fixed_cols,
        rl_to_proove=result_ark_bytes,
        rps=result_plus_seed,
        seed_point=seed_point,
        Domain=domain,
        raw_proof_bytes=raw_bytes,
        transcript_challenge=b"w3f-ring-proof-test",
        padding_rows=padding_rows,
    )

    assert verifier.is_valid(), f"Verification failed for {vector_path.name}"


def get_vector_paths() -> list[Path]:
    vectors_dir = Path(__file__).parent / "vectors" / "others"
    paths = sorted(p for p in vectors_dir.glob("*.json") if p.name != "test_parameters.json")
    if not paths:
        pytest.skip(f"No JSON vectors found in {vectors_dir}")
    return paths


@pytest.mark.parametrize("vector_path", get_vector_paths(), ids=lambda p: p.name)
def test_verify_ring_sig_vectors(vector_path: Path) -> None:
    print(f"Testing vector: {vector_path.name}")
    verify_vector(vector_path)
