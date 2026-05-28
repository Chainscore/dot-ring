from __future__ import annotations

import argparse
import gc
import json
import os
import subprocess
import time
from collections.abc import Callable
from pathlib import Path

from dot_ring import Bandersnatch, Ring, RingRoot, RingVRF
from dot_ring.ring_proof.params import RingProofParams
from dot_ring.ring_proof.pcs.kzg import KZG


def rss_mb() -> float:
    statm = Path("/proc/self/statm")
    if statm.exists():
        pages = int(statm.read_text().split()[1])
        return pages * os.sysconf("SC_PAGE_SIZE") / (1024 * 1024)

    output = subprocess.check_output(["ps", "-o", "rss=", "-p", str(os.getpid())])
    return int(output.strip()) / 1024


def run_probe(
    label: str,
    iterations: int,
    warmup_iterations: int,
    step: int,
    max_growth_mb: float,
    max_steady_growth_mb: float,
    operation: Callable[[], None],
) -> float:
    print(f"{label}: warming up {warmup_iterations} iterations", flush=True)
    for _ in range(warmup_iterations):
        operation()

    # RSS can keep allocator arenas after first use. Measure only after the
    # workload has reached its normal steady-state allocation pattern.
    gc.collect()
    baseline = rss_mb()
    started = time.perf_counter()
    max_growth = 0.0
    samples = [(0, baseline)]
    print(f"{label}: measured_iter=0 rss={baseline:.1f} MB delta=+0.0 MB elapsed=0.0s", flush=True)

    for iteration in range(1, iterations + 1):
        operation()
        if iteration % step == 0 or iteration == iterations:
            gc.collect()
            current = rss_mb()
            growth = current - baseline
            max_growth = max(max_growth, growth)
            samples.append((iteration, current))
            elapsed = time.perf_counter() - started
            print(
                f"{label}: measured_iter={iteration} rss={current:.1f} MB delta={growth:+.1f} MB elapsed={elapsed:.1f}s",
                flush=True,
            )

    final_growth = samples[-1][1] - baseline
    steady_samples = samples[len(samples) // 2 :]
    steady_growth = samples[-1][1] - min(rss for _, rss in steady_samples)
    print(
        f"{label}: final_delta={final_growth:+.1f} MB peak_delta={max_growth:+.1f} MB steady_delta={steady_growth:+.1f} MB",
        flush=True,
    )

    if final_growth > max_growth_mb:
        raise AssertionError(f"{label} RSS grew by {final_growth:.1f} MB after warmup; limit is {max_growth_mb:.1f} MB")

    if steady_growth > max_steady_growth_mb:
        raise AssertionError(f"{label} RSS kept growing by {steady_growth:.1f} MB in the steady-state window; limit is {max_steady_growth_mb:.1f} MB")

    return final_growth


def load_ring_fixture() -> tuple[bytes, bytes, bytes, Ring, RingRoot, bytes]:
    vector_path = Path("tests/vectors/ark-vrf/bandersnatch_ed_sha512_ell2_ring.json")
    with vector_path.open() as f:
        item = json.load(f)[0]

    secret_key = bytes.fromhex(item["sk"])
    alpha = bytes.fromhex(item["alpha"])
    ad = bytes.fromhex(item["ad"])
    keys = RingVRF[Bandersnatch].parse_keys(bytes.fromhex(item["ring_pks"]))
    params = RingProofParams()
    ring = Ring(keys, params)
    ring_root = RingRoot.from_ring(ring, params)
    public_key = RingVRF[Bandersnatch].get_public_key(secret_key)
    return secret_key, alpha, ad, ring, ring_root, public_key


def main() -> int:
    parser = argparse.ArgumentParser(description="Run repeated dot-ring operations and fail on sustained RSS growth.")
    parser.add_argument("--kzg-iters", type=int, default=2000)
    parser.add_argument("--verify-iters", type=int, default=5000)
    parser.add_argument("--prove-iters", type=int, default=200)
    parser.add_argument("--kzg-warmup-iters", type=int, default=200)
    parser.add_argument("--verify-warmup-iters", type=int, default=1000)
    parser.add_argument("--prove-warmup-iters", type=int, default=50)
    parser.add_argument("--max-kzg-growth-mb", type=float, default=1.0)
    parser.add_argument("--max-verify-growth-mb", type=float, default=1.0)
    parser.add_argument("--max-prove-growth-mb", type=float, default=3.0)
    parser.add_argument("--max-kzg-steady-growth-mb", type=float, default=0.5)
    parser.add_argument("--max-verify-steady-growth-mb", type=float, default=0.5)
    parser.add_argument("--max-prove-steady-growth-mb", type=float, default=1.0)
    args = parser.parse_args()

    coeffs = list(range(1, 2049))
    run_probe(
        "kzg_commit_2048",
        args.kzg_iters,
        args.kzg_warmup_iters,
        max(1, args.kzg_iters // 4),
        args.max_kzg_growth_mb,
        args.max_kzg_steady_growth_mb,
        lambda: KZG.commit(coeffs),
    )

    secret_key, alpha, ad, ring, ring_root, public_key = load_ring_fixture()
    proof = RingVRF[Bandersnatch].prove(alpha, ad, secret_key, public_key, ring, ring_root)
    if not proof.verify(alpha, ad, ring, ring_root):
        raise AssertionError("initial proof verification failed")

    run_probe(
        "ring_verify",
        args.verify_iters,
        args.verify_warmup_iters,
        max(1, args.verify_iters // 5),
        args.max_verify_growth_mb,
        args.max_verify_steady_growth_mb,
        lambda: proof.verify(alpha, ad, ring, ring_root),
    )

    def prove_and_verify() -> None:
        fresh_proof = RingVRF[Bandersnatch].prove(alpha, ad, secret_key, public_key, ring, ring_root)
        if not fresh_proof.verify(alpha, ad, ring, ring_root):
            raise AssertionError("proof verification failed")

    run_probe(
        "ring_prove_verify",
        args.prove_iters,
        args.prove_warmup_iters,
        max(1, args.prove_iters // 4),
        args.max_prove_growth_mb,
        args.max_prove_steady_growth_mb,
        prove_and_verify,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
