# Testing Guide

This project comes with a comprehensive test suite to validate the correctness and security of all implemented primitives.  
All unit and integration tests are located under the [`tests/`](./tests) directory.

---

## 📂 Test Structure

The test suite is organized into the following categories:

### 🔹 Curve Operations Tests (`tests/test_curve_ops/`)

Core tests for curve operations and point serialization:
- **`test_curve_ops.py`** - Tests basic curve operations and properties (Covering All Edwards, Weierstrass and Montgomery Curves)
- **`test_curves_s2p_p2s.py`** - Tests point serialization and deserialization for various curve types
- **`test_mg_curve.py`** - Specific tests for Montgomery curve implementation

### 🔹 VRF Tests

#### **IETF VRF Tests** (`tests/test_ietf/`)
Tests the IETF VRF implementation against official test vectors:
- **`test_ietf_ark.py`** - Tests using Arkworks vectors (primarily Bandersnatch curve)
- **`test_ietf_base.py`** - Tests for other supported curves (P-256, P-384, secp256k1, Curve25519, Curve448, Ed25519, etc.)

#### **Pedersen VRF Tests** (`tests/test_pedersen/`)
Tests the Pedersen VRF implementation (commitment-based VRF without exposing public key):
- **`test_pedersen_ark.py`** - Tests using Arkworks vectors (primarily Bandersnatch curve)
- **`test_pedersen_base.py`** - Tests for other supported curves

#### **Ring VRF Tests** (`tests/test_ring_vrf/`)
- **`test_ring_vrf.py`** - Tests the complete Ring VRF implementation combining Pedersen VRF with ring proofs for anonymous VRF signatures

### 🔹 Hash-to-Curve Tests (`tests/test_h2c_suites/`)

Comprehensive RFC 9380-compliant hash-to-curve test suite:
- **`test_h2c_nu.py`** - Tests for Non-Uniform (NU) mapping variants across various curves
- **`test_h2c_ro.py`** - Tests for Random Oracle (RO) mapping variants across various curves
- **`test_bls12_381_G2_ssw_nu.py`** - Specific tests for BLS12-381 G2 Non-Uniform mapping
- **`test_bls12_381_G2_ssw_ro.py`** - Specific tests for BLS12-381 G2 Random Oracle mapping
- **`test_e2c_bandersnatch.py`** - Tests for Bandersnatch encode-to-curve

### 🔹 Other Tests

- **`test_bandersnatch_ark.py`** - Specific tests for Bandersnatch curve compatibility with Arkworks
- **`utils/test_bench_ring.py`** - Benchmarking tests for Ring VRF operations

### 🔹 Test Data

- **`tests/vectors/ark-vrf/`** - Official test vectors from [ark-vrf](https://github.com/davxy/bandersnatch-vrf-spec/tree/main/assets/vectors) for Bandersnatch curve
- **`tests/vectors/base/`** - Base test vectors for various curves
- **`tests/vectors/h2c/`** - [RFC 9380](https://www.rfc-editor.org/rfc/rfc9380.html#name-suite-test-vectors) test vectors for hash-to-curve implementations

---

## ▶️ Running the Tests

Before running tests make sure you have the [Prerequisites](./README.md#prerequisites) installed as mentioned in [README](./README.md).

The tests are written using **pytest**. You can run the entire suite or specific test categories using `uv`:

### Run All Tests
```bash
uv run pytest tests/ -v
```

### Run Specific Test Categories
**All Curve Ops tests:**
```bash
uv run pytest tests/test_curve_ops/ -v
```

**IETF VRF tests:**
```bash
uv run pytest tests/test_ietf/ -v
```

**Pedersen VRF tests:**
```bash
uv run pytest tests/test_pedersen/ -v
```

**Ring VRF tests:**
```bash
uv run pytest tests/test_ring_vrf/ -v
```

**Hash-to-curve tests:**
```bash
uv run pytest tests/test_h2c_suites/ -v
```

### Run Specific Test Files

**Test IETF VRF Base:**
```bash
uv run pytest tests/test_ietf/test_ietf_base.py -v
```

**Test Ring VRF:**
```bash
uv run pytest tests/test_ring_vrf/test_ring_vrf.py -v
```

### Additional Pytest Options

**Run with detailed output:**
```bash
uv run pytest tests/ -vv
```

**Run with coverage report:**
```bash
uv run pytest tests/ --cov=dot_ring --cov-report=html
```

---

## 🎯 Supported Curves

The test suite validates VRF implementations across multiple elliptic curves:

| Curve                | Family | Hash-to-Curve Method |   H2C-Suite-Tests | IETF VRF | Pedersen VRF | Ring VRF |
|----------------------|--------|----------------------|----|----------|--------------|----------|
| **Bandersnatch**     | Twisted Edwards | Elligator 2          | ✅    | ✅       | ✅ | ✅ |
| **P-256/ Secp256r1** | Short Weierstrass | SSWU & TAI           |  ✅   | ✅ | ✅ |  |
| **P-384**            | Short Weierstrass | SSWU                 | ✅    | ✅ | ✅ |  |
| **P-521**            | Short Weierstrass | SSWU                 |  ✅   | ✅   | ✅  |  |
| **secp256k1**        | Short Weierstrass | SSWU                 |  ✅   | ✅ | ✅ |  |
| **Curve25519**       | Montgomery | Elligator 2          | ✅    | ✅  | ✅   |  |
| **Curve448**         | Montgomery | Elligator 2          |  ✅   | ✅  | ✅   |  |
| **Ed25519**          | Twisted Edwards | Elligator 2 & TAI    | ✅    | ✅   | ✅   |  |
| **Ed448**            | Twisted Edwards | Elligator 2          |   ✅  | ✅   | ✅   |  |
| **JubJub**           | Twisted Edwards | TAI                  |   ✅  | ✅   | ✅  |  |
| **BabyJubJub**       | Twisted Edwards | TAI                  |  ✅   | ✅  |  ✅ |  |
| **Bandersnatch_SW**  | Twisted Edwards | TAI                  |  ✅   | ✅ | ✅ |  |



✅ = Implemented and tested |  = Planned/In progress

---

## 📊 Test Coverage

To generate a coverage report:

```bash
pip install pytest-cov
pytest tests/ --cov=dot_ring --cov-report=term-missing
```

For an HTML coverage report:

```bash
pip install pytest-cov
pytest tests/ --cov=dot_ring --cov-report=html
open htmlcov/index.html
```
