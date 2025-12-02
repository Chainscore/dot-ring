#!/usr/bin/env python3
"""
Benchmark script for ring proof generation and verification.

Run with:
    python3.12 bench_ring_proof.py

- Runs multiple warmup iterations
- Measures over multiple iterations
- Reports min, mean, and std deviation
"""

import json
import statistics
import sys
import time
from pathlib import Path

# Add blst to path if needed
sys.path.insert(0, str(Path(__file__).parent / "blst" / "bindings" / "python"))

from dot_ring import Bandersnatch
from dot_ring.vrf.ring.ring_vrf import RingVRF


def load_test_data():
    """Load test vector data."""
    vector_path = (
        Path(__file__).parent
        / "vectors"
        / "ark-vrf"
        / "bandersnatch_ed_sha512_ell2_ring.json"
    )
    with open(vector_path) as f:
        return json.load(f)[0]


def benchmark_ring_proof(warmup_iters: int = 3, bench_iters: int = 10):
    """Benchmark ring proof generation and verification."""

    print("=" * 60)
    print("Ring VRF Proof Benchmark (Python/Cython + gmpy2 + BLST)")
    print("=" * 60)
    print()

    # Load test data
    data = load_test_data()
    s_k = bytes.fromhex(data["sk"])
    alpha = bytes.fromhex(data["alpha"])
    ad = bytes.fromhex(data["ad"])
    ring_pks_bytes = bytes.fromhex(data["ring_pks"])

    # Parse keys once
    keys = RingVRF[Bandersnatch].parse_keys(ring_pks_bytes)
    p_k = RingVRF[Bandersnatch].get_public_key(s_k)

    print(f"Ring size: {len(keys)} members")
    print(f"Warmup iterations: {warmup_iters}")
    print(f"Benchmark iterations: {bench_iters}")
    print()

    # =========================================================================
    # Warmup
    # =========================================================================
    print("Warming up...")
    for _ in range(warmup_iters):
        ring_vrf_proof = RingVRF[Bandersnatch].prove(alpha, ad, s_k, p_k, keys)
        ring_root = RingVRF[Bandersnatch].construct_ring_root(keys)
        ring_vrf_proof.verify(alpha, ad, ring_root)

    # =========================================================================
    # Benchmark Ring Root Construction
    # =========================================================================
    print("\nBenchmarking Ring Root Construction...")
    ring_root_times = []
    ring_root = None
    for _ in range(bench_iters):
        start = time.perf_counter()
        ring_root = RingVRF[Bandersnatch].construct_ring_root(keys)
        elapsed = (time.perf_counter() - start) * 1000
        ring_root_times.append(elapsed)

    # =========================================================================
    # Benchmark Proof Generation
    # =========================================================================
    print("Benchmarking Proof Generation...")
    proof_times = []
    proofs = []
    for _ in range(bench_iters):
        start = time.perf_counter()
        ring_vrf_proof = RingVRF[Bandersnatch].prove(alpha, ad, s_k, p_k, keys)
        elapsed = (time.perf_counter() - start) * 1000
        proof_times.append(elapsed)
        proofs.append(ring_vrf_proof)

    # =========================================================================
    # Benchmark Verification
    # =========================================================================
    print("Benchmarking Verification...")
    verify_times = []
    for proof in proofs:
        start = time.perf_counter()
        result = proof.verify(alpha, ad, ring_root)
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

    print_stats("Ring Root Construction", ring_root_times)
    proof_min, proof_mean = print_stats("Proof Generation", proof_times)
    verify_min, verify_mean = print_stats("Verification", verify_times)

    print("-" * 60)
    print(f"Total (Proof + Verify) Min:  {proof_min + verify_min:8.2f} ms")
    print(f"Total (Proof + Verify) Mean: {proof_mean + verify_mean:8.2f} ms")
    print()

    # Proof size
    proof_bytes = ring_vrf_proof.to_bytes()
    print(f"Proof size: {len(proof_bytes)} bytes")


if __name__ == "__main__":
    benchmark_ring_proof(warmup_iters=2, bench_iters=8)
