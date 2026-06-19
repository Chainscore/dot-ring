#!/usr/bin/env python3
"""Benchmark fresh ring root, proof, and verification timings for one ring size."""

from __future__ import annotations

import argparse
import hashlib
import os
import statistics
import time
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass

from dot_ring import Bandersnatch
from dot_ring.ring_proof.params import RingProofParams
from dot_ring.vrf.ring import RingBatchVerifier, RingRoot, RingVRF
from dot_ring.vrf.ring.members import Ring

SIGNER_INDEX = 3


@dataclass(frozen=True)
class Timing:
    ring_id: bytes
    ring_root_ms: float
    prove_ms: float
    verify_ms: float
    total_ms: float
    proof_size: int


@dataclass(frozen=True)
class ProofFixture:
    proof: RingVRF
    alpha: bytes
    ad: bytes


@dataclass(frozen=True)
class SerializedProofFixture:
    index: int
    proof: bytes
    alpha: bytes
    ad: bytes


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


def _keypair(label: str, sample_index: int, member_index: int = 0) -> tuple[bytes, bytes]:
    public_key, secret_key = Bandersnatch.secret_from_seed(_seed(label, sample_index, member_index))
    return public_key, secret_key


def _ring_keys(ring_size: int, sample_index: int, signer_key: bytes) -> list[bytes]:
    signer_index = min(SIGNER_INDEX, ring_size - 1)
    keys: list[bytes] = []
    for member_index in range(ring_size):
        if member_index == signer_index:
            keys.append(signer_key)
        else:
            public_key, _ = _keypair("ring-member", sample_index, member_index)
            keys.append(public_key)
    return keys


def benchmark_once(ring_size: int, sample_index: int) -> Timing:
    public_key, secret_key = _keypair("signer", sample_index)
    keys = _ring_keys(ring_size, sample_index, public_key)
    params = RingProofParams.from_ring_size(ring_size)
    alpha = b"bench-ring-input" + sample_index.to_bytes(8, "little")
    ad = b"bench-ring-ad" + sample_index.to_bytes(8, "little")

    total_start = time.perf_counter()

    start = time.perf_counter()
    ring = Ring(keys, params)
    ring_root = RingRoot.from_ring(ring, params)
    ring_root_ms = (time.perf_counter() - start) * 1000

    start = time.perf_counter()
    proof = RingVRF[Bandersnatch].prove(alpha, ad, secret_key, public_key, ring, ring_root)
    prove_ms = (time.perf_counter() - start) * 1000

    start = time.perf_counter()
    verified = proof.verify(alpha, ad, ring, ring_root)
    verify_ms = (time.perf_counter() - start) * 1000

    if not verified:
        raise AssertionError("ring proof verification failed")

    return Timing(
        ring_id=ring_root.encode(),
        ring_root_ms=ring_root_ms,
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
    print(f"{label:<12} min={minimum:8.2f} ms  mean={mean:8.2f} ms  max={maximum:8.2f} ms  stddev={stddev:8.2f} ms")


def _batch_sizes(max_size: int) -> list[int]:
    sizes: list[int] = []
    size = 1
    while size <= max_size:
        sizes.append(size)
        size *= 2
    return sizes


def _prove_batch_fixture_range(ring_size: int, start: int, stop: int) -> list[SerializedProofFixture]:
    public_key, secret_key = _keypair("batch-signer", 0)
    keys = _ring_keys(ring_size, 0, public_key)
    params = RingProofParams.from_ring_size(ring_size)
    ring = Ring(keys, params)
    ring_root = RingRoot.from_ring(ring, params)

    fixtures: list[SerializedProofFixture] = []
    for fixture_index in range(start, stop):
        alpha = b"bench-batch-input" + fixture_index.to_bytes(8, "little")
        ad = b"bench-batch-ad" + fixture_index.to_bytes(8, "little")
        proof = RingVRF[Bandersnatch].prove(alpha, ad, secret_key, public_key, ring, ring_root)
        fixtures.append(SerializedProofFixture(fixture_index, proof.encode(), alpha, ad))
    return fixtures


def _chunk_ranges(count: int, workers: int) -> list[tuple[int, int]]:
    chunk_count = min(count, workers)
    base, remainder = divmod(count, chunk_count)
    ranges: list[tuple[int, int]] = []
    start = 0
    for chunk_index in range(chunk_count):
        stop = start + base + (1 if chunk_index < remainder else 0)
        ranges.append((start, stop))
        start = stop
    return ranges


def _build_batch_fixtures_parallel(ring_size: int, fixture_count: int, workers: int) -> tuple[Ring, RingRoot, list[ProofFixture]]:
    public_key, _ = _keypair("batch-signer", 0)
    keys = _ring_keys(ring_size, 0, public_key)
    params = RingProofParams.from_ring_size(ring_size)
    ring = Ring(keys, params)
    ring_root = RingRoot.from_ring(ring, params)

    if workers <= 1:
        serialized = _prove_batch_fixture_range(ring_size, 0, fixture_count)
    else:
        serialized = []
        with ProcessPoolExecutor(max_workers=workers) as executor:
            futures = [executor.submit(_prove_batch_fixture_range, ring_size, start, stop) for start, stop in _chunk_ranges(fixture_count, workers)]
            for future in futures:
                serialized.extend(future.result())

    serialized.sort(key=lambda fixture: fixture.index)
    fixtures = [
        ProofFixture(
            RingVRF[Bandersnatch].decode(fixture.proof),
            fixture.alpha,
            fixture.ad,
        )
        for fixture in serialized
    ]
    return ring, ring_root, fixtures


def run(
    ring_size: int,
    samples: int,
    max_batch_size: int,
    batch_fixtures: int | None,
    batch_workers: int,
) -> None:
    if samples <= 0:
        raise ValueError("samples must be positive")
    if batch_fixtures is None:
        batch_fixtures = max_batch_size

    timings = [benchmark_once(ring_size, sample_index) for sample_index in range(samples)]

    print(f"Ring proof benchmark: n={ring_size}, samples={samples}")
    print()
    print("sample  ring_root_ms  prove_ms  verify_ms  total_ms")
    for timing in timings:
        print(
            f"{timing.ring_id.hex()[:8]:>6}  {timing.ring_root_ms:>12.2f}  {timing.prove_ms:>8.2f}  {timing.verify_ms:>9.2f}  {timing.total_ms:>8.2f}"
        )

    print()
    _print_stats("ring_root", [timing.ring_root_ms for timing in timings])
    _print_stats("prove", [timing.prove_ms for timing in timings])
    _print_stats("verify", [timing.verify_ms for timing in timings])
    _print_stats("total", [timing.total_ms for timing in timings])
    print(f"proof_size: {timings[-1].proof_size} bytes")

    fixture_count, workers = batch_fixtures, batch_workers
    if max_batch_size <= 0:
        return
    if fixture_count <= 0:
        raise ValueError("batch fixture count must be positive")
    if fixture_count < max_batch_size:
        raise ValueError("batch fixture count must be at least batch max so every batch entry is unique")
    if samples <= 0:
        raise ValueError("batch samples must be positive")
    if workers <= 0:
        raise ValueError("batch workers must be positive")
    workers = min(workers, fixture_count)

    print()
    print(f"Batch verify: max_n={max_batch_size}, unique_fixtures={fixture_count}")
    print(f"Preparing proofs... | workers={workers}")

    ring, ring_root, fixtures = _build_batch_fixtures_parallel(ring_size, fixture_count, workers)

    print()
    print("batch_n  batch_ms  batch_ms_per_proof")
    for batch_size in _batch_sizes(max_batch_size):
        verifier = RingBatchVerifier()
        start = time.perf_counter()
        for fixture in fixtures[:batch_size]:
            verifier.push(fixture.proof, fixture.alpha, fixture.ad, ring, ring_root)
        verified = verifier.verify()
        elapsed_ms = (time.perf_counter() - start) * 1000
        if not verified:
            raise AssertionError(f"batch verification failed for n={batch_size}")

        print(f"{batch_size:>7}  {elapsed_ms:>13.2f} {elapsed_ms / batch_size:>18.2f}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Benchmark fresh ring root, prove, and verify timings.")
    parser.add_argument("n", type=int, nargs="?", default=1024, help="ring size")
    parser.add_argument("-s", "--samples", type=int, default=3, help="number of fresh samples to run")
    parser.add_argument("--batch-max", type=int, default=256, help="largest batched verification size to benchmark")
    parser.add_argument("--batch-fixtures", type=int, default=None, help="number of unique proofs to generate; defaults to --batch-max")
    parser.add_argument("--batch-workers", type=int, default=os.cpu_count() or 1, help="parallel worker processes for batch proof generation")
    args = parser.parse_args()
    run(args.n, args.samples, args.batch_max, args.batch_fixtures, args.batch_workers)


if __name__ == "__main__":
    main()
