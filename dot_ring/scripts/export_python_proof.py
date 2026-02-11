"""
Export Python-generated ring proofs to arkworks-compatible JSON.

This script generates multiple ring proof variants using the Python implementation and
exports them in the same format as Rust's arkworks-serialized proof vectors.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# Add project root to path to import dot_ring modules
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from py_ecc.optimized_bls12_381 import normalize as nm

from dot_ring.curve.specs.bandersnatch import Bandersnatch, BandersnatchParams, BandersnatchPoint
from dot_ring.ring_proof.curve.bandersnatch import TwistedEdwardCurve
from dot_ring.ring_proof.params import RingProofParams
from dot_ring.ring_proof.pcs.srs import srs
from dot_ring.vrf.ring.ring_root import Ring, RingRoot
from dot_ring.vrf.ring.ring_vrf import RingVRF
from tests.utils.python_to_rust_serde import (
    serialize_bls12_381_g1,
    serialize_bls12_381_g2,
    serialize_fq_field_element,
    serialize_ring_proof,
)

Blinding_Base = (
    int.from_bytes(bytes.fromhex("e8c5e337ffbd7839ed5aaee576faae32eea01bff684125758d874fa909e8980d"), "little"),
    int.from_bytes(bytes.fromhex("e93da06b869766b158d20b843ec648cc68e0b7ba2f7083acf0f154205d04e23e"), "little"),
)
SeedPoint = (
    int.from_bytes(bytes.fromhex("20f354ea2af5f890e0cfac3b044aca2335fc26fa900fbe429fb059b0df319553"), "little"),
    int.from_bytes(bytes.fromhex("6e5574f9077fb76c885c36196a832dbadd64142d305be5487724967acf959520"), "little"),
)

blinding_factor = int.from_bytes(bytes.fromhex("2e98974f0b99a70d4fbe7c1ea62a5ada75c899deb30e9d27f9e5da79177c0619"), "big")


@dataclass(frozen=True)
class VariantSpec:
    name: str
    domain_size: int
    ring_size: int
    padding_rows: int = 4
    radix_domain_size: int | None = None
    prover_index: int = 42


DEFAULT_VARIANTS = [
    VariantSpec(
        name="ring_proof_ring64_domain512.json",
        domain_size=512,
        ring_size=64,
    ),
    VariantSpec(
        name="ring_proof_ring128_domain512.json",
        domain_size=512,
        ring_size=128,
    ),
    VariantSpec(
        name="ring_proof_ring256_domain1024.json",
        domain_size=1024,
        ring_size=256,
    ),
    VariantSpec(
        name="ring_proof_ring1024_domain2048.json",
        domain_size=2048,
        ring_size=1000,
    ),
]


def generate_test_keys(
    num_keys: int,
    prover_index: int,
) -> tuple[list[bytes], list[tuple[int, int]], int]:
    """
    Generate deterministic, valid Bandersnatch public keys.

    Args:
        num_keys: Number of keys in the ring
        prover_index: Index of the prover's key

    Returns:
        Tuple of (list of compressed key bytes, list of key points, prover index)
    """
    if num_keys < 1:
        raise ValueError("num_keys must be >= 1")
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


def export_variant(variant: VariantSpec, output_dir: Path) -> dict[str, Any]:
    """Generate and export a single proof variant."""
    params = RingProofParams(
        domain_size=variant.domain_size,
        max_ring_size=variant.ring_size,
        padding_rows=variant.padding_rows,
        radix_domain_size=variant.radix_domain_size,
    )

    if variant.ring_size > params.max_effective_ring_size:
        raise ValueError(
            f"ring_size {variant.ring_size} exceeds max supported size {params.max_effective_ring_size} "
            f"for domain {variant.domain_size} with padding_rows={variant.padding_rows}"
        )

    # Deterministic test parameters
    secret_bits = max(1, blinding_factor.bit_length())
    max_secret_bits = params.domain_size - params.padding_rows - params.max_ring_size
    if max_secret_bits < 1:
        raise ValueError(
            "ring_size too large for any secret_t bits: "
            f"ring_size={params.max_ring_size}, domain_size={params.domain_size}, padding_rows={params.padding_rows}"
        )
    if secret_bits > max_secret_bits:
        raise ValueError(
            "secret_t bit length exceeds available rows: "
            f"{secret_bits} > {max_secret_bits} (ring_size={params.max_ring_size}, "
            f"domain_size={params.domain_size}, padding_rows={params.padding_rows})"
        )
    prover_index = min(variant.prover_index, variant.ring_size - 1)
    keys_bytes, keys_points, prover_index = generate_test_keys(num_keys=variant.ring_size, prover_index=prover_index)

    # Build ring and ring root
    ring = Ring(keys_bytes, params)
    ring_root = RingRoot.from_ring(ring, params)

    # Producer key
    producer_key_bytes = keys_bytes[prover_index]
    producer_key_point = keys_points[prover_index]

    # Generate ring proof using a Rust-test-compatible transcript label
    proof_components = RingVRF[Bandersnatch].generate_bls_signature(
        blinding_factor=blinding_factor,
        producer_key=producer_key_bytes,
        ring=ring,
        transcript_challenge=b"w3f-ring-proof-test",
        ring_root=ring_root,
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
        nm(ring_root.px.commitment),
        nm(ring_root.py.commitment),
        nm(ring_root.s.commitment),
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
                "domain_size": params.domain_size,
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

    output_file = output_dir / variant.name
    output_file.parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, "w") as f:
        json.dump(result, f, indent=2)

    print(f"✓ Proof exported to: {output_file}")
    print(f"  Proof size: {len(proof_bytes)} bytes")
    print(f"  Ring size: {params.max_ring_size} keys")
    print(f"  Domain size: {params.domain_size}")

    return result


def export_proof_to_json(output_dir: str | None = None, variants: list[VariantSpec] | None = None) -> list[dict[str, Any]]:
    """
    Generate Python ring proofs and export them to JSON in arkworks format.

    Args:
        output_dir: Directory to save JSON files (default: tests/vectors/others)
        variants: Optional list of VariantSpec entries to export

    Returns:
        List of dictionaries containing proofs and parameters
    """
    if output_dir is None:
        output_dir = str(Path(__file__).parent.parent.parent / "tests" / "vectors" / "others")

    output_path = Path(output_dir)
    variant_list = variants or DEFAULT_VARIANTS

    results = []
    for variant in variant_list:
        results.append(export_variant(variant, output_path))

    return results


if __name__ == "__main__":
    output_dir = sys.argv[1] if len(sys.argv) > 1 else None
    export_proof_to_json(output_dir=output_dir)
