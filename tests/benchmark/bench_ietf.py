#!/usr/bin/env python3
"""Benchmark fresh IETF/Tiny VRF proof and verification timings."""

from __future__ import annotations

import argparse
import hashlib
import statistics
import time
from dataclasses import dataclass

from dot_ring import Bandersnatch
from dot_ring.vrf.ietf import TinyVRF


@dataclass(frozen=True)
class Timing:
    prove_ms: float
    verify_ms: float
    total_ms: float
    proof_size: int


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


def benchmark_once(sample_index: int) -> Timing:
    public_key, secret_key = Bandersnatch.secret_from_seed(_seed("ietf-signer", sample_index))
    alpha = b"bench-ietf-input" + sample_index.to_bytes(8, "little")
    ad = b"bench-ietf-ad" + sample_index.to_bytes(8, "little")
    salt = b"bench-ietf-salt" + sample_index.to_bytes(8, "little")

    total_start = time.perf_counter()

    start = time.perf_counter()
    proof = TinyVRF[Bandersnatch].prove(alpha, secret_key, ad, salt)
    prove_ms = (time.perf_counter() - start) * 1000

    start = time.perf_counter()
    verified = proof.verify(public_key, alpha, ad, salt)
    verify_ms = (time.perf_counter() - start) * 1000

    if not verified:
        raise AssertionError("IETF VRF verification failed")

    return Timing(
        prove_ms=prove_ms,
        verify_ms=verify_ms,
        total_ms=(time.perf_counter() - total_start) * 1000,
        proof_size=len(proof.encode()),
    )


def _stats(values: list[float]) -> tuple[float, float, float, float]:
    stddev = statistics.stdev(values) if len(values) > 1 else 0.0
    return min(values), statistics.mean(values), max(values), stddev


def _print_stats(label: str, values: list[float]) -> None:
    minimum, mean, maximum, stddev = _stats(values)
    print(f"{label:<8} min={minimum:8.2f} ms  mean={mean:8.2f} ms  max={maximum:8.2f} ms  stddev={stddev:8.2f} ms")


def run(samples: int) -> None:
    if samples <= 0:
        raise ValueError("samples must be positive")

    timings = [benchmark_once(sample_index) for sample_index in range(samples)]

    print(f"IETF/Tiny VRF benchmark: samples={samples}")
    print("Scope: each sample builds fresh key material, input, proof, and verification.")
    print()
    print("sample  prove_ms  verify_ms  total_ms")
    for index, timing in enumerate(timings, start=1):
        print(f"{index:>6}  {timing.prove_ms:>8.2f}  {timing.verify_ms:>9.2f}  {timing.total_ms:>8.2f}")

    print()
    _print_stats("prove", [timing.prove_ms for timing in timings])
    _print_stats("verify", [timing.verify_ms for timing in timings])
    _print_stats("total", [timing.total_ms for timing in timings])
    print(f"proof_size: {timings[-1].proof_size} bytes")


def main() -> None:
    parser = argparse.ArgumentParser(description="Benchmark fresh IETF/Tiny VRF prove and verify timings.")
    parser.add_argument("-s", "--samples", type=int, default=30, help="number of fresh samples to run")
    args = parser.parse_args()
    run(args.samples)


if __name__ == "__main__":
    main()
