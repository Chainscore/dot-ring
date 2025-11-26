# Ring VRF Benchmark 

- Benchmark vector: tests/vectors/ark-vrf/bandersnatch_ed_sha512_ell2_ring.json (8 keys).
- Runtime environment: Python 3.12.11
- Device: Macbook M1 Pro, ARM M1 Max, 64 GB RAM

### Ring Root Construction
```
  Min:       34.70 ms
  Mean:      35.32 ms
  Stddev:     0.67 ms
```

### Proof Generation:
```
  Min:      263.58 ms
  Mean:     265.66 ms
  Stddev:     1.54 ms
```

### Verification
```
  Min:        5.59 ms
  Mean:       5.73 ms
  Stddev:     0.14 ms
```