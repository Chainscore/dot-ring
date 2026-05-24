# VRF Benchmarks

Benchmark results for `dot-ring` VRF implementations on Bandersnatch curve.

- **Runtime**: Python 3.13
- **Device**: MacBook Pro, M1 Max - ARM, 64 GB RAM
- **Suite**: `Bandersnatch-SHA512-ELL2-v1`
- **Vectors**: `tests/vectors/ark-vrf/bandersnatch_*_*.json`
- **Baseline**: ark-vrf `benches/SUMMARY.md`, quick mode, AMD Ryzen Threadripper 3970X

---

## IETF / Tiny VRF

IETF VRF-AD proof.

| Operation | Min | Mean | Stddev | ark-vrf | x |
|-----------|--------------|---------------|-----------------|---------|--------------------|
| Proof Generation | 1.67 ms | 1.78 ms | 0.09 ms | 185.4 us | 9.6x |
| Verification | 1.58 ms | 1.66 ms | 0.06 ms | 194.5 us | 8.5x |

**Proof size**: 96 bytes

---

## Pedersen VRF

VRF with Pedersen commitment for public key blinding.

| Operation | Min | Mean | Stddev | ark-vrf | x |
|-----------|--------------|---------------|-----------------|---------|--------------------|
| Proof Generation | 2.30 ms | 2.38 ms | 0.07 ms | 374.6 us | 6.4x |
| Verification | 1.88 ms | 1.97 ms | 0.06 ms | 215.4 us | 9.1x |

**Proof size**: 192 bytes

---

## Ring VRF

Ring VRF with SNARK-based ring membership proof.

**Proof size**: 784 bytes (constant across all ring sizes)

### 8-member ring (domain size: 512)

| Operation | Min | Mean | Stddev |
|-----------|--------------|---------------|-----------------|
| Ring Root Construction | 28.07 ms | 28.28 ms | 0.14 ms |
| Proof Generation | 153.35 ms | 155.18 ms | 1.42 ms |
| Verification | 4.05 ms | 4.35 ms | 0.19 ms |

ark-vrf's published summary does not include an 8-member ring row.

### 1023-member ring (domain size: 2048)

| Operation | Min | Mean | Stddev | ark-vrf | x |
|-----------|--------------|---------------|-----------------|---------|--------------------|
| Ring Root Construction | 330.76 ms | 334.71 ms | 5.07 ms | 138.5 ms | 2.4x |
| Proof Generation | 525.28 ms | 543.04 ms | 29.13 ms | 482.2 ms | 1.1x |
| Verification | 4.09 ms | 4.22 ms | 0.14 ms | 3.37 ms | 1.3x |

---

## Running Benchmarks

```bash
# IETF / Tiny VRF
uv run python tests/benchmark/bench_ietf.py

# Pedersen VRF
uv run python tests/benchmark/bench_pedersen.py

# Ring VRF (8-member ring, domain size 512)
uv run python tests/benchmark/bench_ring_proof.py

# Ring VRF (1023-member ring, domain size 2048)
uv run python tests/benchmark/bench_ring_large.py
```
