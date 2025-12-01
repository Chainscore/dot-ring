import json
import os
import sys
from pathlib import Path

# Add tests directory to path to import utils
sys.path.insert(0, str(Path(__file__).parent))

from dot_ring.curve.specs.bandersnatch import Bandersnatch
from dot_ring.vrf.pedersen.pedersen import PedersenVRF

from .profiler import Profiler

HERE = os.path.dirname(__file__)
RESULTS_DIR = os.path.join(HERE, "results")


def load_test_data():
    """Load test vectors from JSON file - returns only first test case"""
    file_path = os.path.join(
        HERE, "../vectors", "ark-vrf/bandersnatch_ed_sha512_ell2_pedersen.json"
    )
    with open(file_path) as f:
        data = json.load(f)
    return [data[0]]  # Return only first test case


def test_bench_pedersen_prove():
    """Benchmark Pedersen VRF proof generation with profiling"""
    data = load_test_data()

    # Create results directory
    os.makedirs(RESULTS_DIR, exist_ok=True)

    for index in range(len(data)):
        item = data[index]
        s_k = bytes.fromhex(item["sk"])
        alpha = bytes.fromhex(item["alpha"])
        ad = bytes.fromhex(item["ad"])

        # Benchmark proof generation with profiling
        with Profiler(
            f"pedersen_prove_sample_{index + 1}",
            save_stats=True,
            print_stats=True,
            sort_by="cumulative",
            limit=40,
        ):
            proof = PedersenVRF[Bandersnatch].prove(alpha, s_k, ad)

        # Verify correctness
        assert proof.output_point.point_to_string().hex() == item["gamma"]

    print("📊 Profile saved to: perf/results/")


def test_bench_pedersen_verify():
    """Benchmark Pedersen VRF verification with profiling"""
    data = load_test_data()

    # Create results directory
    os.makedirs(RESULTS_DIR, exist_ok=True)

    for index in range(len(data)):
        item = data[index]
        s_k = bytes.fromhex(item["sk"])
        alpha = bytes.fromhex(item["alpha"])
        ad = bytes.fromhex(item["ad"])

        # Generate proof first
        proof = PedersenVRF[Bandersnatch].prove(alpha, s_k, ad)

        # Benchmark verification with profiling
        with Profiler(
            f"pedersen_verify_sample_{index + 1}",
            save_stats=True,
            print_stats=True,
            sort_by="cumulative",
            limit=40,
        ):
            result = proof.verify(alpha, ad)

        assert result, "Verification Failed"

    print("📊 Profile saved to: perf/results/")
