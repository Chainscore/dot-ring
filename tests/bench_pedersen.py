#!/usr/bin/env python3
"""
Benchmark script for Pedersen VRF proof generation and verification.

Run with:
    python tests/bench_pedersen.py

- Runs multiple warmup iterations
- Measures over multiple iterations
- Reports min, mean, and std deviation
"""

import json
import time
import statistics
import sys
from pathlib import Path

from dot_ring import Bandersnatch
from dot_ring.vrf.pedersen.pedersen import PedersenVRF


def load_test_data():
    """Load test vector data."""
    vector_path = Path(__file__).parent / "vectors" / "ark-vrf" / "bandersnatch_ed_sha512_ell2_pedersen.json"
    with open(vector_path) as f:
        return json.load(f)[0]


def benchmark_pedersen_vrf(warmup_iters: int = 5, bench_iters: int = 100):
    """Benchmark Pedersen VRF proof generation and verification."""
    
    print("=" * 60)
    print("Pedersen VRF Benchmark (Python/Cython + gmpy2)")
    print("=" * 60)
    print()
    
    # Load test data
    data = load_test_data()
    s_k = bytes.fromhex(data['sk'])
    alpha = bytes.fromhex(data['alpha'])
    ad = bytes.fromhex(data['ad'])
    
    # Get public key
    p_k = PedersenVRF[Bandersnatch].get_public_key(s_k)
    
    print(f"Curve: Bandersnatch (Twisted Edwards)")
    print(f"Warmup iterations: {warmup_iters}")
    print(f"Benchmark iterations: {bench_iters}")
    print()
    
    # =========================================================================
    # Warmup
    # =========================================================================
    print("Warming up...")
    for _ in range(warmup_iters):
        proof = PedersenVRF[Bandersnatch].prove(alpha, s_k, ad)
        proof.verify(alpha, ad)
    
    # =========================================================================
    # Benchmark Proof Generation
    # =========================================================================
    print("Benchmarking Proof Generation...")
    proof_times = []
    proofs = []
    for _ in range(bench_iters):
        start = time.perf_counter()
        proof = PedersenVRF[Bandersnatch].prove(alpha, s_k, ad)
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
        result = proof.verify(alpha, ad)
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
    benchmark_pedersen_vrf(warmup_iters=5, bench_iters=100)
