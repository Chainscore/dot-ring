import json
from pathlib import Path
from typing import Any

import pytest

from dot_ring.ring_proof.params import RingProofParams
from dot_ring.vrf.ietf import ThinVRF, TinyVRF
from dot_ring.vrf.pedersen import PedersenVRF
from dot_ring.vrf.ring import Ring, RingRoot, RingVRF
from scripts.generate_test_vectors import RING_SUITES, SUITES, Suite

VECTORS = Path(__file__).parent / "vectors" / "dot-ring"


def load(suite: Suite, scheme: str) -> list[dict[str, Any]]:
    return json.loads((VECTORS / f"{suite.prefix}_{scheme}.json").read_text())


def ring_proof_bytes(vector: dict[str, Any]) -> bytes:
    return bytes.fromhex(
        vector["gamma"]
        + vector["proof_pk_com"]
        + vector["proof_r"]
        + vector["proof_ok"]
        + vector["proof_s"]
        + vector["proof_sb"]
        + vector["ring_proof"]
    )


@pytest.mark.parametrize("suite", SUITES)
def test_dot_ring_tiny_vectors(suite: Suite) -> None:
    for vector in load(suite, "tiny"):
        alpha = bytes.fromhex(vector["alpha"])
        ad = bytes.fromhex(vector["ad"])
        proof_bytes = bytes.fromhex(vector["gamma"] + vector["proof_c"] + vector["proof_s"])
        proof = TinyVRF[suite.curve].from_bytes(proof_bytes)

        assert TinyVRF[suite.curve].get_public_key(bytes.fromhex(vector["sk"])).hex() == vector["pk"]
        assert suite.curve.point.encode_to_curve(alpha).point_to_string().hex() == vector["h"]
        assert proof.verify(bytes.fromhex(vector["pk"]), alpha, ad)
        assert TinyVRF[suite.curve].proof_to_hash(proof.output_point).hex() == vector["beta"]


@pytest.mark.parametrize("suite", SUITES)
def test_dot_ring_thin_vectors(suite: Suite) -> None:
    for vector in load(suite, "thin"):
        alpha = bytes.fromhex(vector["alpha"])
        ad = bytes.fromhex(vector["ad"])
        proof_bytes = bytes.fromhex(vector["gamma"] + vector["proof_r"] + vector["proof_s"])
        proof = ThinVRF[suite.curve].from_bytes(proof_bytes)

        assert proof.verify(bytes.fromhex(vector["pk"]), alpha, ad)
        assert ThinVRF[suite.curve].proof_to_hash(proof.output_point).hex() == vector["beta"]


@pytest.mark.parametrize("suite", SUITES)
def test_dot_ring_pedersen_vectors(suite: Suite) -> None:
    for vector in load(suite, "pedersen"):
        alpha = bytes.fromhex(vector["alpha"])
        ad = bytes.fromhex(vector["ad"])
        proof_bytes = bytes.fromhex(
            vector["gamma"] + vector["proof_pk_com"] + vector["proof_r"] + vector["proof_ok"] + vector["proof_s"] + vector["proof_sb"]
        )
        proof = PedersenVRF[suite.curve].from_bytes(proof_bytes)

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
        proof = RingVRF[suite.curve].from_bytes(ring_proof_bytes(vector))
        assert proof.pedersen_proof is not None

        assert len(keys) == vector["ring_size"]
        assert keys[vector["prover_idx"]] == bytes.fromhex(vector["pk"])
        assert ring_root.to_bytes().hex() == vector["ring_pks_com"]
        assert proof.verify(alpha, ad, ring, ring_root)
        assert RingVRF[suite.curve].proof_to_hash(proof.pedersen_proof.output_point).hex() == vector["beta"]
