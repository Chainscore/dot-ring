#!/usr/bin/env python3
"""
Benchmark script for IETF VRF proof generation and verification.

Run with:
    python tests/bench_ietf.py

- Runs multiple warmup iterations
- Measures over multiple iterations
- Reports min, mean, and std deviation
"""

import json
import statistics
import time
from pathlib import Path

from dot_ring import Bandersnatch
from dot_ring.vrf.ietf.ietf import IETF_VRF


def load_test_data():
    """Load test vector data."""
    vector_path = Path(__file__).parent / "vectors" / "ark-vrf" / "bandersnatch_ed_sha512_ell2_ietf.json"
    with open(vector_path) as f:
        return json.load(f)[0]


def benchmark_ietf_vrf(warmup_iters: int = 5, bench_iters: int = 100):
    """Benchmark IETF VRF proof generation and verification."""

    print("=" * 60)
    print("IETF VRF Benchmark (Python/Cython + gmpy2)")
    print("=" * 60)
    print()

    # Load test data
    data = load_test_data()
    s_k = bytes.fromhex(data["sk"])
    alpha = bytes.fromhex(data["alpha"])
    ad = bytes.fromhex(data["ad"])
    salt = bytes.fromhex(data.get("salt", ""))

    # Get public key
    p_k = IETF_VRF[Bandersnatch].get_public_key(s_k)

    print("Curve: Bandersnatch (Twisted Edwards)")
    print(f"Warmup iterations: {warmup_iters}")
    print(f"Benchmark iterations: {bench_iters}")
    print()

    # =========================================================================
    # Warmup
    # =========================================================================
    print("Warming up...")
    for _ in range(warmup_iters):
        proof = IETF_VRF[Bandersnatch].prove(alpha, s_k, ad, salt)
        proof.verify(p_k, alpha, ad, salt)

    # =========================================================================
    # Benchmark Proof Generation
    # =========================================================================
    print("Benchmarking Proof Generation...")
    proof_times = []
    proofs = []
    for _ in range(bench_iters):
        start = time.perf_counter()
        proof = IETF_VRF[Bandersnatch].prove(alpha, s_k, ad, salt)
        elapsed = (time.perf_counter() - start) * 1000
        proof_times.append(elapsed)
        proofs.append(proof)

    # =========================================================================
    # Benchmark Verification
    # =========================================================================
    print("Benchmarking Verification...")
    verify_times = []
    for proof in proofs:
        start = time.perf_counter()
        result = proof.verify(p_k, alpha, ad, salt)
        elapsed = (time.perf_counter() - start) * 1000
        verify_times.append(elapsed)
        assert result, "Verification failed!"

    # =========================================================================
    # Results
    # =========================================================================
    print()
    print("=" * 60)
    print("RESULTS")
    print("=" * 60)
    print()

    def print_stats(name: str, times: list):
        min_t = min(times)
        mean_t = statistics.mean(times)
        std_t = statistics.stdev(times) if len(times) > 1 else 0
        print(f"{name}:")
        print(f"  Min:    {min_t:8.2f} ms")
        print(f"  Mean:   {mean_t:8.2f} ms")
        print(f"  Stddev: {std_t:8.2f} ms")
        print()
        return min_t, mean_t

    proof_min, proof_mean = print_stats("Proof Generation", proof_times)
    verify_min, verify_mean = print_stats("Verification", verify_times)

    print("-" * 60)
    print(f"Total (Proof + Verify) Min:  {proof_min + verify_min:8.2f} ms")
    print(f"Total (Proof + Verify) Mean: {proof_mean + verify_mean:8.2f} ms")
    print()

    # Proof size
    proof_bytes = proofs[0].to_bytes()
    print(f"Proof size: {len(proof_bytes)} bytes")


if __name__ == "__main__":
    benchmark_ietf_vrf(warmup_iters=5, bench_iters=100)
