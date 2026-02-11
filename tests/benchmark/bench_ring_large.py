import statistics
import sys
import time
from pathlib import Path

# Add blst to path if needed
sys.path.insert(0, str(Path(__file__).parent / "blst" / "bindings" / "python"))

from dot_ring import Bandersnatch, Ring, RingRoot, RingVRF
from dot_ring.keygen import secret_from_seed
from dot_ring.ring_proof.params import RingProofParams


def generate_ring_keys(ring_size: int) -> tuple[list[bytes], bytes, bytes]:
    """Generate ring keys for benchmarking."""
    print(f"Generating {ring_size} keys for the ring...")

    keys = []
    prover_sk = None
    prover_pk = None

    # Generate keys deterministically from seeds
    for i in range(ring_size):
        seed = f"ring_member_{i}".encode()
        pk, sk = secret_from_seed(seed, Bandersnatch)
        keys.append(pk)

        # Use the middle key as the prover
        if i == ring_size // 2:
            prover_sk = sk
            prover_pk = pk

    assert prover_sk is not None
    assert prover_pk is not None
    print(f"Generated {len(keys)} keys")

    return keys, prover_sk, prover_pk


def benchmark_large_ring_proof(
    ring_size: int = 1023,
    domain_size: int = 2048,
    warmup_iters: int = 4,
    bench_iters: int = 5,
):
    """Benchmark 1024 ring-sized proof generation and verification over 2048 domain."""

    print("=" * 60)
    print("1024 Ring VRF Proof Benchmark")
    print("=" * 60)
    print()
    print(f"Ring size: {ring_size} members")
    print(f"Domain size: {domain_size}")
    print(f"Warmup iterations: {warmup_iters}")
    print(f"Benchmark iterations: {bench_iters}")
    print()

    # Generate test data
    keys, s_k, p_k = generate_ring_keys(ring_size)
    alpha = b"test_alpha"
    ad = b""

    # Create parameters for large ring
    params = RingProofParams(domain_size=domain_size, max_ring_size=ring_size)

    print("Parameters configured:")
    print(f"  Domain size: {params.domain_size}")
    print(f"  Max ring size: {params.max_ring_size}")
    print(f"  Padding rows: {params.padding_rows}")
    print()

    # =========================================================================
    # Construct Ring Root (one-time setup)
    # =========================================================================
    start = time.perf_counter()
    ring = Ring(keys, params)
    ring_root = RingRoot.from_ring(ring, params)
    ring_root_time = (time.perf_counter() - start) * 1000
    print(f"Ring root constructed in {ring_root_time:.2f} ms")
    print()

    # =========================================================================
    # Warmup
    # =========================================================================
    print("Warming up...")
    for i in range(warmup_iters):
        print(f"  Warmup iteration {i + 1}/{warmup_iters}...")
        # Pass ring_root to avoid rebuilding it
        ring = Ring(keys, params)
        ring_root = RingRoot.from_ring(ring, params)
        ring_vrf_proof = RingVRF[Bandersnatch].prove(alpha, ad, s_k, p_k, ring, ring_root)
        ring_vrf_proof.verify(alpha, ad, ring, ring_root)
    print("Warmup complete")

    # =========================================================================
    # Benchmark Ring Root Construction
    # =========================================================================
    print("\nBenchmarking ring root construction...")
    root_const_times = []
    for _ in range(bench_iters):
        start = time.perf_counter()
        ring = Ring(keys, params)
        ring_root = RingRoot.from_ring(ring, params)
        elapsed = (time.perf_counter() - start) * 1000
        root_const_times.append(elapsed)

    # =========================================================================
    # Benchmark Proof Generation
    # =========================================================================
    print("\nBenchmarking Proof Generation...")
    proof_times = []
    proofs = []
    for i in range(bench_iters):
        print(f"  Iteration {i + 1}/{bench_iters}...")
        start = time.perf_counter()
        # Pass ring_root to avoid rebuilding - this is the key optimization!
        ring_vrf_proof = RingVRF[Bandersnatch].prove(alpha, ad, s_k, p_k, ring, ring_root)
        elapsed = (time.perf_counter() - start) * 1000
        proof_times.append(elapsed)
        proofs.append(ring_vrf_proof)

    # =========================================================================
    # Benchmark Verification
    # =========================================================================
    print("\nBenchmarking Verification...")
    verify_times = []
    for i, proof in enumerate(proofs):
        print(f"  Iteration {i + 1}/{bench_iters}...")
        start = time.perf_counter()
        result = proof.verify(alpha, ad, ring, ring_root)
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

    print()
    proof_min, proof_mean = print_stats("Ring Root Construction", root_const_times)
    proof_min, proof_mean = print_stats("Proof Generation", proof_times)
    verify_min, verify_mean = print_stats("Verification", verify_times)

    print("-" * 60)
    print(f"Total (Proof + Verify) Min:  {proof_min + verify_min:8.2f} ms")
    print(f"Total (Proof + Verify) Mean: {proof_mean + verify_mean:8.2f} ms")
    print()

    # Proof size
    proof_bytes = ring_vrf_proof.to_bytes()
    print(f"Proof size: {len(proof_bytes)} bytes")
    print()

    return {
        "ring_root_time": ring_root_time,
        "proof": proof_times,
        "verify": verify_times,
        "proof_size": len(proof_bytes),
    }


if __name__ == "__main__":
    benchmark_large_ring_proof(ring_size=1023, domain_size=2048, warmup_iters=1, bench_iters=3)
