import os
import sys
from pathlib import Path

# Add tests directory to path to import utils
sys.path.insert(0, str(Path(__file__).parent))

from dot_ring.curve.specs.bandersnatch import Bandersnatch
from dot_ring.keygen import secret_from_seed
from dot_ring.vrf.ietf.ietf import IETF_VRF

from ..utils.profiler import Profiler

HERE = os.path.dirname(__file__)
RESULTS_DIR = os.path.join(HERE, "results")


def load_test_data():
    """Create deterministic benchmark data."""
    pk, sk = secret_from_seed(bytes(32), Bandersnatch)
    return [{"sk": sk.hex(), "pk": pk.hex(), "alpha": b"bench input data".hex(), "ad": b"ad".hex(), "salt": ""}]


def test_bench_ietf_prove():
    """Benchmark IETF VRF proof generation with profiling"""
    data = load_test_data()

    # Create results directory
    os.makedirs(RESULTS_DIR, exist_ok=True)

    for index in range(len(data)):
        item = data[index]
        s_k = bytes.fromhex(item["sk"])
        alpha = bytes.fromhex(item["alpha"])
        ad = bytes.fromhex(item["ad"])
        salt = bytes.fromhex(item.get("salt", ""))

        # Benchmark proof generation with profiling
        with Profiler(
            f"ietf_prove_sample_{index + 1}",
            save_stats=True,
            print_stats=True,
            sort_by="cumulative",
            limit=40,
        ):
            proof = IETF_VRF[Bandersnatch].prove(alpha, s_k, ad, salt)

        assert proof.verify(bytes.fromhex(item["pk"]), alpha, ad, salt)

    print("📊 Profile saved to: perf/results/")


def test_bench_ietf_verify():
    """Benchmark IETF VRF verification with profiling"""
    data = load_test_data()

    # Create results directory
    os.makedirs(RESULTS_DIR, exist_ok=True)

    for index in range(len(data)):
        item = data[index]
        s_k = bytes.fromhex(item["sk"])
        alpha = bytes.fromhex(item["alpha"])
        ad = bytes.fromhex(item["ad"])
        salt = bytes.fromhex(item.get("salt", ""))

        # Generate proof first
        proof = IETF_VRF[Bandersnatch].prove(alpha, s_k, ad, salt)
        pk = IETF_VRF[Bandersnatch].get_public_key(s_k)

        # Benchmark verification with profiling
        with Profiler(
            f"ietf_verify_sample_{index + 1}",
            save_stats=True,
            print_stats=True,
            sort_by="cumulative",
            limit=40,
        ):
            result = proof.verify(pk, alpha, ad, salt)

        assert result, "Verification Failed"

    print("📊 Profile saved to: perf/results/")
