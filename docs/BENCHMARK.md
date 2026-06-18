# VRF Benchmarks

Benchmark results for `dot-ring` VRF implementations on Bandersnatch curve.

- **Runtime**: Python 3.13
- **Device**: MacBook Pro, M1 Max - ARM, 64 GB RAM
- **Suite**: `Bandersnatch-SHA512-ELL2-v1`
- **Vectors**: `tests/vectors/ark-vrf/bandersnatch_*_*.json`
- **Baseline**: ark-vrf `benches/SUMMARY.md`, quick mode, AMD Ryzen Threadripper 3970X
- **Local run**: 2026-05-25

---

## IETF / Tiny VRF

IETF VRF-AD proof.

| Operation | Min | Mean | Stddev | ark-vrf | x |
|-----------|-----|------|--------|---------|---|
| Proof Generation | 2.21 ms | 2.65 ms | 0.85 ms | 185.4 us | 14.3x |
| Verification | 1.97 ms | 2.28 ms | 0.59 ms | 194.5 us | 11.7x |

**Proof size**: 80 bytes

---

## Thin VRF

Thin VRF with `(R, s)` proofs.

| Operation | Min | Mean | Stddev | ark-vrf | x |
|-----------|-----|------|--------|---------|---|
| Proof Generation | 2.21 ms | 2.55 ms | 0.56 ms | 184.8 us | 13.8x |
| Verification | 1.99 ms | 2.15 ms | 0.20 ms | 192.4 us | 11.2x |

**Proof size**: 96 bytes

---

## Pedersen VRF

VRF with Pedersen commitment for public key blinding.

| Operation | Min | Mean | Stddev | ark-vrf | x |
|-----------|-----|------|--------|---------|---|
| Proof Generation | 2.40 ms | 2.64 ms | 0.68 ms | 374.6 us | 7.1x |
| Verification | 1.74 ms | 1.83 ms | 0.07 ms | 215.4 us | 8.5x |

**Proof size**: 192 bytes

---

## Ring VRF

Ring VRF with SNARK-based ring membership proof.

**Proof size**: 784 bytes (constant across all ring sizes)

### 8-member ring (domain size: 512)

| Operation | Min | Mean | Stddev |
|-----------|-----|------|--------|
| Ring Root Construction | 27.03 ms | 27.80 ms | 0.75 ms |
| Proof Generation | 152.31 ms | 154.03 ms | 1.29 ms |
| Verification | 3.70 ms | 3.95 ms | 0.19 ms |

### 1023-member ring (domain size: 2048)

| Operation | Min | Mean | Stddev | ark-vrf | x |
|-----------|-----|------|--------|---------|---|
| Ring Root Construction | 327.11 ms | 334.16 ms | 9.18 ms | 138.5 ms | 2.4x |
| Proof Generation | 527.04 ms | 534.57 ms | 12.48 ms | 482.2 ms | 1.1x |
| Verification | 3.81 ms | 3.99 ms | 0.24 ms | 3.37 ms | 1.2x |

---

## Running Benchmarks

```bash
# IETF / Tiny VRF
uv run python tests/benchmark/bench_ietf.py

# Thin VRF
uv run python scripts/benchmark_rust_baseline.py --output /tmp/dot-ring-benchmark.md --ring-batch-max 0

# Pedersen VRF
uv run python tests/benchmark/bench_pedersen.py

# Ring VRF (8-member ring, domain size 512)
uv run python tests/benchmark/bench_ring_proof.py

# Ring VRF (1023-member ring, domain size 2048)
uv run python tests/benchmark/bench_ring_large.py
```
