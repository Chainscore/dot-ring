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

Ring VRF with SNARK-based ring membership proof (8-member ring).

| Operation | Min | Mean | Stddev |
|-----------|-----|------|--------|
| Ring Root Construction | 28.11 ms | 28.54 ms | 0.42 ms |
| Proof Generation | 251.16 ms | 253.68 ms | 1.88 ms |
| Verification | 3.98 ms | 4.16 ms | 0.12 ms |

**Proof size**: 784 bytes

---

## Running Benchmarks

```bash
# IETF VRF
uv run python tests/bench_ietf.py

# Pedersen VRF
uv run python tests/bench_pedersen.py

# Ring VRF
uv run python tests/bench_ring_proof.py
```