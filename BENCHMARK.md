# Ring VRF Benchmark 

- Benchmark vector: tests/vectors/ark-vrf/bandersnatch_ed_sha512_ell2_ring.json (8 keys).
- Runtime environment: Python 3.12.11
- Device: Macbook Pro, M1 Max - ARM, 64 GB RAM

### Ring Root Construction
```
  Min:       34.21 ms
  Mean:      35.02 ms
  Stddev:     0.58 ms
```

### Proof Generation:
```
  Min:      257.16 ms
  Mean:     259.32 ms
  Stddev:     1.08 ms
```

### Verification
```
  Min:        4.08 ms
  Mean:       4.24 ms
  Stddev:     0.10 ms
```