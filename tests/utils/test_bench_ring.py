import json
import os
import sys
from pathlib import Path

# Add tests directory to path to import utils
sys.path.insert(0, str(Path(__file__).parent))

from dot_ring.curve.specs.bandersnatch import Bandersnatch
from dot_ring.vrf.ring.ring_vrf import RingVRF

from .profiler import Profiler

HERE = os.path.dirname(__file__)
RESULTS_DIR = os.path.join(HERE, "results")


def load_test_data():
    """Load test vectors from JSON file - returns only first test case"""
    file_path = os.path.join(
        HERE, "../vectors", "dot-ring/bandersnatch_sha-512_ell2_ring.json"
    )
    with open(file_path) as f:
        data = json.load(f)
    return [data[0]]  # Return only first test case


def test_bench_ring_prove():
    """Benchmark Ring VRF proof generation with profiling"""
    data = load_test_data()

    # Create results directory
    os.makedirs(RESULTS_DIR, exist_ok=True)

    for index in range(len(data)):
        item = data[index]
        s_k = bytes.fromhex(item["sk"])
        alpha = bytes.fromhex(item["alpha"])
        ad = bytes.fromhex(item["ad"])
        keys = RingVRF[Bandersnatch].parse_keys(bytes.fromhex(item["ring_pks"]))

        # Store ring size
        ring_root = RingVRF[Bandersnatch].construct_ring_root(keys)
        p_k = RingVRF[Bandersnatch].get_public_key(s_k)

        # Benchmark proof generation with profiling
        with Profiler(
            f"ring_prove_sample_{index + 1}",
            save_stats=True,
            print_stats=False,
            sort_by="cumulative",
            limit=25,
        ):
            ring_vrf_proof = RingVRF[Bandersnatch].prove(alpha, ad, s_k, p_k, keys)

        # Verify correctness
        assert p_k.hex() == item["pk"], "Invalid Public Key"
        assert ring_root.to_bytes().hex() == item["ring_pks_com"], "Invalid Ring Root"
        expected_proof = (
            item["gamma"]
            + item["proof_pk_com"]
            + item["proof_r"]
            + item["proof_ok"]
            + item["proof_s"]
            + item["proof_sb"]
            + item["ring_proof"]
        )
        assert ring_vrf_proof.to_bytes().hex() == expected_proof, "Unexpected Proof"

    print("📊 Profile saved to: perf/results/")


def test_bench_ring_verify():
    """Benchmark Ring VRF verification with profiling"""
    data = load_test_data()

    # Create results directory
    os.makedirs(RESULTS_DIR, exist_ok=True)

    for index in range(len(data)):
        item = data[index]
        alpha = bytes.fromhex(item["alpha"])
        ad = bytes.fromhex(item["ad"])
        ring_root_bytes = bytes.fromhex(item["ring_pks_com"])

        proof_hex = (
            item["gamma"]
            + item["proof_pk_com"]
            + item["proof_r"]
            + item["proof_ok"]
            + item["proof_s"]
            + item["proof_sb"]
            + item["ring_proof"]
        )
        proof_bytes = bytes.fromhex(proof_hex)

        # Parse proof from bytes
        ring_vrf_proof = RingVRF[Bandersnatch].from_bytes(proof_bytes)

        # Benchmark verification with profiling
        with Profiler(
            f"ring_verify_sample_{index + 1}",
            save_stats=True,
            print_stats=False,
            sort_by="cumulative",
            limit=100,
        ):
            result = ring_vrf_proof.verify(alpha, ad, ring_root_bytes)

        assert result, "Verification Failed"

    print("📊 Profile saved to: perf/results/")
