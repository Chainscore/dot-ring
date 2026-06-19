from pathlib import Path
from typing import Any

import pytest

from dot_ring.ring_proof.params import RingProofParams
from dot_ring.vrf.ietf import ThinVRF, TinyVRF
from dot_ring.vrf.pedersen import PedersenVRF
from dot_ring.vrf.ring import Ring, RingRoot, RingVRF
from scripts.generate_test_vectors import RING_SUITES, SUITES, Suite
from tests.vector_helpers import load_json_vectors, pedersen_proof_bytes, ring_proof_bytes, thin_proof_bytes, tiny_proof_bytes

VECTORS = Path(__file__).parent / "vectors" / "dot-ring"


def load(suite: Suite, scheme: str) -> list[dict[str, Any]]:
    return load_json_vectors(VECTORS, f"{suite.prefix}_{scheme}.json")


@pytest.mark.parametrize("suite", SUITES)
def test_dot_ring_tiny_vectors(suite: Suite) -> None:
    for vector in load(suite, "tiny"):
        alpha = bytes.fromhex(vector["alpha"])
        ad = bytes.fromhex(vector["ad"])
        proof_bytes = tiny_proof_bytes(vector)
        proof = TinyVRF[suite.curve].decode(proof_bytes)

        assert suite.curve.public_key_from_secret(bytes.fromhex(vector["sk"])).hex() == vector["pk"]
        assert suite.curve.encode_to_curve(alpha).point_to_string().hex() == vector["h"]
        assert proof.verify(bytes.fromhex(vector["pk"]), alpha, ad)
        assert TinyVRF[suite.curve].proof_to_hash(proof.output_point).hex() == vector["beta"]


@pytest.mark.parametrize("suite", SUITES)
def test_dot_ring_thin_vectors(suite: Suite) -> None:
    for vector in load(suite, "thin"):
        alpha = bytes.fromhex(vector["alpha"])
        ad = bytes.fromhex(vector["ad"])
        proof_bytes = thin_proof_bytes(vector)
        proof = ThinVRF[suite.curve].decode(proof_bytes)

        assert proof.verify(bytes.fromhex(vector["pk"]), alpha, ad)
        assert ThinVRF[suite.curve].proof_to_hash(proof.output_point).hex() == vector["beta"]


@pytest.mark.parametrize("suite", SUITES)
def test_dot_ring_pedersen_vectors(suite: Suite) -> None:
    for vector in load(suite, "pedersen"):
        alpha = bytes.fromhex(vector["alpha"])
        ad = bytes.fromhex(vector["ad"])
        proof_bytes = pedersen_proof_bytes(vector)
        proof = PedersenVRF[suite.curve].decode(proof_bytes)

        assert proof.verify(alpha, ad)
        assert PedersenVRF[suite.curve].proof_to_hash(proof.output_point).hex() == vector["beta"]


@pytest.mark.parametrize("suite", RING_SUITES)
def test_dot_ring_ring_vectors(suite: Suite) -> None:
    for vector in load(suite, "ring"):
        alpha = bytes.fromhex(vector["alpha"])
        ad = bytes.fromhex(vector["ad"])
        keys = RingVRF[suite.curve].parse_keys(bytes.fromhex(vector["ring_pks"]))
        params = RingProofParams(test_vectors=True, cv=suite.curve)
        ring = Ring(keys, params)
        ring_root = RingRoot.from_ring(ring, params)
        proof = RingVRF[suite.curve].decode(ring_proof_bytes(vector))
        assert proof.pedersen_proof is not None

        assert len(keys) == vector["ring_size"]
        assert keys[vector["prover_idx"]] == bytes.fromhex(vector["pk"])
        assert ring_root.encode().hex() == vector["ring_pks_com"]
        assert proof.verify(alpha, ad, ring, ring_root)
        assert RingVRF[suite.curve].proof_to_hash(proof.pedersen_proof.output_point).hex() == vector["beta"]
