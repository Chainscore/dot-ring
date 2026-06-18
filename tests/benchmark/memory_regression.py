#!/usr/bin/env python3
"""Run simple RSS regression probes for repeated dot-ring operations."""

from __future__ import annotations

import argparse
import gc
import hashlib
import os
import subprocess
import time
from collections.abc import Callable
from pathlib import Path

from dot_ring import Bandersnatch
from dot_ring.keygen import secret_from_seed
from dot_ring.ring_proof.params import RingProofParams
from dot_ring.ring_proof.pcs.kzg import KZG
from dot_ring.vrf.ring import RingRoot, RingVRF
from dot_ring.vrf.ring.members import Ring

SIGNER_INDEX = 3
RSS_EPSILON_MB = 0.1


def rss_mb() -> float:
    statm = Path("/proc/self/statm")
    if statm.exists():
        pages = int(statm.read_text().split()[1])
        return pages * os.sysconf("SC_PAGE_SIZE") / (1024 * 1024)

    output = subprocess.check_output(["ps", "-o", "rss=", "-p", str(os.getpid())])
    return int(output.strip()) / 1024


def _seed(*parts: object) -> bytes:
    h = hashlib.sha256()
    for part in parts:
        match part:
            case bytes():
                h.update(part)
            case int():
                h.update(part.to_bytes(8, "little", signed=False))
            case str():
                h.update(part.encode())
            case _:
                raise TypeError(f"unsupported seed part: {type(part).__name__}")
        h.update(b"\0")
    return h.digest()


def _ring_fixture(ring_size: int, sample_index: int) -> tuple[bytes, bytes, bytes, bytes, Ring, RingRoot]:
    public_key, secret_key = secret_from_seed(_seed("memory-signer", sample_index), Bandersnatch)
    signer_index = min(SIGNER_INDEX, ring_size - 1)
    keys: list[bytes] = []
    for member_index in range(ring_size):
        if member_index == signer_index:
            keys.append(public_key)
        else:
            member_key, _ = secret_from_seed(_seed("memory-ring-member", sample_index, member_index), Bandersnatch)
            keys.append(member_key)

    params = RingProofParams.from_ring_size(ring_size)
    ring = Ring(keys, params)
    ring_root = RingRoot.from_ring(ring, params)
    alpha = b"memory-ring-input" + sample_index.to_bytes(8, "little")
    ad = b"memory-ring-ad" + sample_index.to_bytes(8, "little")
    return secret_key, public_key, alpha, ad, ring, ring_root


def _ring_proof_fixture(ring_size: int, sample_index: int) -> tuple[bytes, bytes, Ring, RingRoot, RingVRF]:
    secret_key, public_key, alpha, ad, ring, ring_root = _ring_fixture(ring_size, sample_index)
    proof = RingVRF[Bandersnatch].prove(alpha, ad, secret_key, public_key, ring, ring_root)
    if not proof.verify(alpha, ad, ring, ring_root):
        raise AssertionError("initial ring proof verification failed")
    return alpha, ad, ring, ring_root, proof


def _verify_or_raise(proof: RingVRF, alpha: bytes, ad: bytes, ring: Ring, ring_root: RingRoot) -> None:
    if not proof.verify(alpha, ad, ring, ring_root):
        raise AssertionError("verification failed")


def run_probe(
    label: str,
    iterations: int,
    warmup_iterations: int,
    max_growth_mb: float,
    max_steady_growth_mb: float,
    operation: Callable[[int], None],
) -> None:
    if iterations <= 0:
        return

    print(f"{label}: warmup={warmup_iterations} iterations={iterations}", flush=True)
    for index in range(warmup_iterations):
        operation(index)

    gc.collect()
    baseline = rss_mb()
    started = time.perf_counter()
    step = max(1, iterations // 5)
    samples = [(0, baseline)]
    print(f"{label}: measured_iter=0 rss={baseline:.1f} MB delta=+0.0 MB elapsed=0.0s", flush=True)

    for index in range(1, iterations + 1):
        operation(warmup_iterations + index)
        if index % step == 0 or index == iterations:
            gc.collect()
            current = rss_mb()
            samples.append((index, current))
            print(
                f"{label}: measured_iter={index} rss={current:.1f} MB "
                f"delta={current - baseline:+.1f} MB elapsed={time.perf_counter() - started:.1f}s",
                flush=True,
            )

    final_growth = samples[-1][1] - baseline
    steady_samples = samples[len(samples) // 2 :]
    steady_growth = samples[-1][1] - min(rss for _, rss in steady_samples)
    peak_growth = max(rss for _, rss in samples) - baseline
    print(
        f"{label}: final_delta={final_growth:+.1f} MB peak_delta={peak_growth:+.1f} MB steady_delta={steady_growth:+.1f} MB",
        flush=True,
    )

    if final_growth > max_growth_mb + RSS_EPSILON_MB:
        raise AssertionError(f"{label} RSS grew by {final_growth:.1f} MB after warmup; limit is {max_growth_mb:.1f} MB")
    if steady_growth > max_steady_growth_mb + RSS_EPSILON_MB:
        raise AssertionError(f"{label} RSS kept growing by {steady_growth:.1f} MB in the steady-state window; limit is {max_steady_growth_mb:.1f} MB")


def main() -> None:
    parser = argparse.ArgumentParser(description="Run simple RSS regression probes for dot-ring operations.")
    parser.add_argument("-n", "--ring-size", type=int, default=8, help="ring size for ring probes")
    parser.add_argument("--kzg-iters", type=int, default=20)
    parser.add_argument("--verify-iters", type=int, default=50)
    parser.add_argument("--prove-iters", type=int, default=10)
    parser.add_argument("--warmups", type=int, default=3)
    parser.add_argument("--max-kzg-growth-mb", type=float, default=8.0)
    parser.add_argument("--max-verify-growth-mb", type=float, default=16.0)
    parser.add_argument("--max-prove-growth-mb", type=float, default=32.0)
    parser.add_argument("--max-steady-growth-mb", type=float, default=1.0)
    args = parser.parse_args()

    coeffs = list(range(1, 2049))
    run_probe(
        "kzg_commit_2048",
        args.kzg_iters,
        args.warmups,
        args.max_kzg_growth_mb,
        args.max_steady_growth_mb,
        lambda _: KZG.commit(coeffs),
    )

    alpha, ad, ring, ring_root, proof = _ring_proof_fixture(args.ring_size, 0)
    run_probe(
        "ring_verify",
        args.verify_iters,
        args.warmups,
        args.max_verify_growth_mb,
        args.max_steady_growth_mb,
        lambda _: _verify_or_raise(proof, alpha, ad, ring, ring_root),
    )

    def prove_and_verify(sample_index: int) -> None:
        secret_key, public_key, fresh_alpha, fresh_ad, fresh_ring, fresh_root = _ring_fixture(args.ring_size, sample_index)
        fresh_proof = RingVRF[Bandersnatch].prove(fresh_alpha, fresh_ad, secret_key, public_key, fresh_ring, fresh_root)
        if not fresh_proof.verify(fresh_alpha, fresh_ad, fresh_ring, fresh_root):
            raise AssertionError("proof verification failed")

    run_probe(
        "ring_prove_verify",
        args.prove_iters,
        args.warmups,
        args.max_prove_growth_mb,
        args.max_steady_growth_mb,
        prove_and_verify,
    )


if __name__ == "__main__":
    main()
