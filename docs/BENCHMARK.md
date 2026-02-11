# VRF Benchmarks

Benchmark results for `dot-ring` VRF implementations on Bandersnatch curve.

- **Runtime**: Python 3.13
- **Device**: MacBook Pro, M1 Max - ARM, 64 GB RAM
- **Vectors**: `tests/vectors/ark-vrf/bandersnatch_ed_sha512_ell2_*.json`

---

## IETF VRF

Standard IETF-compliant VRF (RFC 9381).

| Operation | Min | Mean | Stddev |
|-----------|-----|------|--------|
| Proof Generation | 1.67 ms | 1.78 ms | 0.09 ms |
| Verification | 1.58 ms | 1.66 ms | 0.06 ms |

**Proof size**: 96 bytes

---

## Pedersen VRF

VRF with Pedersen commitment for public key blinding.

| Operation | Min | Mean | Stddev |
|-----------|-----|------|--------|
| Proof Generation | 2.30 ms | 2.38 ms | 0.07 ms |
| Verification | 1.88 ms | 1.97 ms | 0.06 ms |

**Proof size**: 192 bytes

---

## Ring VRF

Ring VRF with SNARK-based ring membership proof.
**Proof size**: 784 bytes (constant across all ring sizes)

### 8-member ring (domain size: 512)

| Operation | Min | Mean | Stddev |
|-----------|-----|------|--------|
| Ring Root Construction | 28.07 ms | 28.28 ms | 0.14 ms |
| Proof Generation | 153.35 ms | 155.18 ms | 1.42 ms |
| Verification | 4.05 ms | 4.35 ms | 0.19 ms |

### 1023-member ring (domain size: 2048)

| Operation | Min | Mean | Stddev |
|-----------|-----|------|--------|
| Ring Root Construction | 330.76 ms | 334.71 ms | 5.07 ms |
| Proof Generation | 525.28 ms | 543.04 ms | 29.13 ms |
| Verification | 4.09 ms | 4.22 ms | 0.14 ms |


---

## Running Benchmarks

```bash
# IETF VRF
uv run python tests/benchmark/bench_ietf.py

# Pedersen VRF
uv run python tests/benchmark/bench_pedersen.py

# Ring VRF (8-member ring, domain size 512)
uv run python tests/benchmark/bench_ring_proof.py

# Ring VRF (1023-member ring, domain size 2048)
uv run python tests/benchmark/bench_ring_large.py
```