"""
Export Python-generated ring proof to arkworks-compatible JSON.

This script generates a ring proof using the Python implementation and exports it
in the same format as Rust's arkworks-serialized proof vectors.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

# Add project root to path to import dot_ring modules
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from py_ecc.optimized_bls12_381 import normalize as nm

from dot_ring.curve.specs.bandersnatch import Bandersnatch, BandersnatchParams, BandersnatchPoint
from dot_ring.ring_proof.columns.columns import PublicColumnBuilder as PC
from dot_ring.ring_proof.constants import Blinding_Base, MAX_RING_SIZE, SeedPoint, SIZE
from dot_ring.ring_proof.curve.bandersnatch import TwistedEdwardCurve
from dot_ring.ring_proof.pcs.srs import srs
from dot_ring.vrf.ring.ring_vrf import RingVRF
from tests.utils.python_to_rust_serde import (
    serialize_bls12_381_g1,
    serialize_bls12_381_g2,
    serialize_fq_field_element,
    serialize_ring_proof,
)


def generate_test_keys(
    num_keys: int = MAX_RING_SIZE,
    prover_index: int = 42,
) -> tuple[list[bytes], list[tuple[int, int]], int]:
    """
    Generate deterministic, valid Bandersnatch public keys.

    Args:
        num_keys: Number of keys in the ring (<= MAX_RING_SIZE)
        prover_index: Index of the prover's key

    Returns:
        Tuple of (list of compressed key bytes, list of key points, prover index)
    """
    if prover_index >= num_keys:
        raise ValueError("prover_index must be < num_keys")

    base = BandersnatchPoint(BandersnatchParams.GENERATOR_X, BandersnatchParams.GENERATOR_Y)

    keys_bytes: list[bytes] = []
    keys_points: list[tuple[int, int]] = []
    for i in range(1, num_keys + 1):
        pt = base * i
        keys_points.append((int(pt.x), int(pt.y)))
        keys_bytes.append(pt.point_to_string())

    return keys_bytes, keys_points, prover_index


def export_proof_to_json(output_path: str | None = None) -> dict[str, Any]:
    """
    Generate a Python ring proof and export it to JSON in arkworks format.

    Args:
        output_path: Path to save JSON file (default: tests/vectors/others/ring_proof_rust_generated.json)

    Returns:
        Dictionary containing proof and parameters
    """
    # Deterministic test parameters
    blinding_factor = 12345
    keys_bytes, keys_points, prover_index = generate_test_keys(num_keys=MAX_RING_SIZE, prover_index=42)

    # Build fixed columns (this mutates the list, so use a copy)
    ring_keys_for_columns = list(keys_points)
    fixed_cols = PC().build(ring_keys_for_columns)

    # Producer key
    producer_key_bytes = keys_bytes[prover_index]
    producer_key_point = keys_points[prover_index]

    # Generate ring proof using a Rust-test-compatible transcript label
    proof_components = RingVRF[Bandersnatch].generate_bls_signature(
        blinding_factor=blinding_factor,
        producer_key=producer_key_bytes,
        keys=keys_bytes,
        transcript_challenge=b"w3f-ring-proof-test",
    )

    # Compute result point (blinded public key)
    result_point = TwistedEdwardCurve.mul(blinding_factor, Blinding_Base)
    result_point = TwistedEdwardCurve.add(result_point, producer_key_point)

    # Unpack proof components
    (
        c_b,
        c_acc_ip,
        c_acc_x,
        c_acc_y,
        p_x_zeta,
        p_y_zeta,
        s_zeta,
        b_zeta,
        acc_ip_zeta,
        acc_x_zeta,
        acc_y_zeta,
        c_q,
        l_zeta_omega,
        phi_z,
        phi_zw,
    ) = proof_components

    # Normalize commitments to affine coordinates
    c_b_affine = nm(c_b.commitment)
    c_acc_ip_affine = nm(c_acc_ip.commitment)
    c_acc_x_affine = nm(c_acc_x.commitment)
    c_acc_y_affine = nm(c_acc_y.commitment)
    c_q_affine = nm(c_q.commitment)
    phi_z_affine = nm(phi_z.proof)
    phi_zw_affine = nm(phi_zw.proof)

    # Serialize proof bytes (for size/debug)
    proof_bytes = serialize_ring_proof(
        column_commitments=[c_b_affine, c_acc_ip_affine, c_acc_x_affine, c_acc_y_affine],
        columns_at_zeta=[p_x_zeta, p_y_zeta, s_zeta, b_zeta, acc_ip_zeta, acc_x_zeta, acc_y_zeta],
        quotient_commitment=c_q_affine,
        lin_at_zeta_omega=l_zeta_omega,
        agg_at_zeta_proof=phi_z_affine,
        lin_at_zeta_omega_proof=phi_zw_affine,
    )

    # Serialize first 3 SRS points for verifier key
    srs_g1_0 = serialize_bls12_381_g1(srs.g1_points[0])
    srs_g2_0 = serialize_bls12_381_g2(srs.g2_points[0])
    srs_g2_1 = serialize_bls12_381_g2(srs.g2_points[1])

    # Serialize fixed column commitments
    fixed_cols_cmts_affine = [
        nm(fixed_cols[0].commitment),
        nm(fixed_cols[1].commitment),
        nm(fixed_cols[2].commitment),
    ]

    verifier_key_bytes = bytearray()
    verifier_key_bytes.extend(srs_g1_0)
    verifier_key_bytes.extend(srs_g2_0)
    verifier_key_bytes.extend(srs_g2_1)
    for commitment in fixed_cols_cmts_affine:
        verifier_key_bytes.extend(serialize_bls12_381_g1(commitment))

    # Concatenate column commitments (4 G1 points)
    column_commitments_concat = (
        serialize_bls12_381_g1(c_b_affine)
        + serialize_bls12_381_g1(c_acc_ip_affine)
        + serialize_bls12_381_g1(c_acc_x_affine)
        + serialize_bls12_381_g1(c_acc_y_affine)
    ).hex()

    # Concatenate columns at zeta (7 field elements)
    columns_at_zeta_concat = (
        serialize_fq_field_element(p_x_zeta)
        + serialize_fq_field_element(p_y_zeta)
        + serialize_fq_field_element(s_zeta)
        + serialize_fq_field_element(b_zeta)
        + serialize_fq_field_element(acc_ip_zeta)
        + serialize_fq_field_element(acc_x_zeta)
        + serialize_fq_field_element(acc_y_zeta)
    ).hex()

    result = {
        "proof": {
            "agg_at_zeta_proof": serialize_bls12_381_g1(phi_z_affine).hex(),
            "column_commitments": column_commitments_concat,
            "columns_at_zeta": columns_at_zeta_concat,
            "lin_at_zeta_omega": serialize_fq_field_element(l_zeta_omega).hex(),
            "lin_at_zeta_omega_proof": serialize_bls12_381_g1(phi_zw_affine).hex(),
            "quotient_commitment": serialize_bls12_381_g1(c_q_affine).hex(),
        },
        "verifier_key": {
            "verification_key": verifier_key_bytes.hex(),
        },
        "metadata": {
            "parameters": {
                "domain_size": SIZE,
                "ring_size": len(keys_points),
                "h": {
                    "x": serialize_fq_field_element(Blinding_Base[0]).hex(),
                    "y": serialize_fq_field_element(Blinding_Base[1]).hex(),
                },
                "seed": {
                    "x": serialize_fq_field_element(SeedPoint[0]).hex(),
                    "y": serialize_fq_field_element(SeedPoint[1]).hex(),
                },
                "result": {
                    "x": serialize_fq_field_element(result_point[0]).hex(),
                    "y": serialize_fq_field_element(result_point[1]).hex(),
                },
            },
        },
    }

    if output_path is None:
        output_path = str(
            Path(__file__).parent.parent.parent
            / "tests"
            / "vectors"
            / "others"
            / "ring_proof_python_generated.json"
        )

    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)

    with open(output_file, "w") as f:
        json.dump(result, f, indent=2)

    print(f"✓ Proof exported to: {output_file}")
    print(f"  Proof size: {len(proof_bytes)} bytes")
    print(f"  Ring size: {len(keys_points)} keys")
    print(f"  Prover index: {prover_index}")

    return result


if __name__ == "__main__":
    output_path = sys.argv[1] if len(sys.argv) > 1 else None
    export_proof_to_json(output_path)
