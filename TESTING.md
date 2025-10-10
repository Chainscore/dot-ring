# Testing Guide

This project comes with a comprehensive test suite to validate the correctness and security of all implemented primitives.  
All unit and integration tests are located under the [`tests/`](./tests) directory.

---

## 📂 Test Structure

The test suite is organized into the following categories:

### 🔹 VRF Tests (`tests/test_vrfs/`)

#### **IETF VRF Tests** (`test_ietf/`)
Tests the IETF VRF implementation against official test vectors for multiple curves:
- **`test_bandersnatch_ietf.py`** - Bandersnatch curve (Twisted Edwards) with Elligator 2
- **`test_p256_sswu_ietf.py`** - P-256 (NIST) curve with SSWU mapping
- **`test_p384_sswu_ietf.py`** - P-384 (NIST) curve with SSWU mapping
- **`test_secp256K1_sswu_ietf.py`** - secp256k1 curve with SSWU mapping

Test vectors are located in `tests/ark-vrf/` for Bandersnatch and `tests/test_vrfs/vectors/` for other curves.

#### **Pedersen VRF Tests** (`test_pedersen/`)
Tests the Pedersen VRF implementation (commitment-based VRF without exposing public key):
- **`test_bandersnatch_pedersen.py`** - Bandersnatch curve implementation
- **`test_p256_sswu_pedersen.py`** - P-256 curve implementation
- **`test_p384_sswu_pedersen.py`** - P-384 curve implementation
- **`test_secp256k1_sswu_pedersen.py`** - secp256k1 curve implementation

#### **Ring Proof Tests** (`test_ring_proof/`)
- **`test_ring_proof.py`** - Validates ring proofs using BLS12-381 signatures, including ring root construction and signature verification

#### **Ring VRF Tests** (`test_ring_vrf/`)
- **`test_ring_vrf.py`** - Tests the complete Ring VRF implementation combining Pedersen VRF with ring proofs for anonymous VRF signatures

### 🔹 Hash-to-Curve Tests (`tests/test_h2c_suites/`)

Comprehensive RFC 9380-compliant hash-to-curve test suite covering multiple curves and mapping methods:


#### **Weierstrass Curves (SSWU, Elligator 2)**
- **P-256**: `test_p256_ssw_e2c_ro.py`, `test_p256_ssw_e2c_nu.py`
- **P-384**: `test_p384_ssw_e2c_ro.py`, `test_p384_ssw_e2c_nu.py`
- **P-521**: `test_p521_ssw_e2c_ro.py`, `test_p521_ssw_e2c_nu.py`
- **Secp256k1**: `test_secp256k1_e2c_ro.py`, `test_secp256k1_e2c_nu.py`
- **BLS12_381_G1**: `bls12_381_G1_ssw_ro.py`, `bls12_381_G1_ssw_nu.py`
- **BLS12_381_G2**: `bls12_381_G2_ssw_ro.py`, `bls12_381_G2_ssw_nu.py`

### **Montgomery Curves (Elligator 2)**
- **Curve25519**: `test_curve25519_e2c_ell2_ro.py`, `test_curve25519_e2c_ell2_nu.py`
- **Curve448**: `test_curve448_e2c_ell2_ro.py`, `test_curve448_e2c_ell2_nu.py`

#### **Edwards Curves (Elligator 2)**
- **Ed25519**: `test_ed25519_ell2_ro.py`, `test_ed25519_ell2_nu.py`
- **Ed448**: `test_ed448_ell2_ro.py`, `test_ed448_ell2_nu.py`
- **Bandersnatch**: `test_e2c_bandersnatch.py`


**Note**: `_ro` suffix indicates Random Oracle variant, `_nu` suffix indicates Non-Uniform variant.

### 🔹 Integration Tests

- **`test_all_vrfs.py`** - High-level integration test that generates and verifies signatures for all implemented VRF schemes of BandersnatchCurve

### 🔹 Test Data

- **`tests/ark-vrf/`** - Official test vectors from [ark-vrf](https://github.com/davxy/bandersnatch-vrf-spec/tree/main/assets/vectors) for Bandersnatch curve
- **`tests/test_vrfs/vectors/`** - Sample Test vectors for P-256, P-384, secp256k1, Curve25519, and Curve448
- **`tests/test_h2c_suites/vectors/`** - [RFC 9380](https://www.rfc-editor.org/rfc/rfc9380.html#name-suite-test-vectors) test vectors for hash-to-curve implementations

---

## ▶️ Running the Tests

Before running tests make sure you have the [Prerequisites](./README.md#prerequisites) installed as mentioned in [README](./README.md).

The tests are written using **pytest**. You can run the entire suite or specific test categories:

### Run All Tests
```bash
pytest tests/ -v
```

### Run Specific Test Categories

**All VRF tests:**
```bash
pytest tests/test_vrfs/ -v
```

**IETF VRF tests only:**
```bash
pytest tests/test_vrfs/test_ietf/ -v
```

**Pedersen VRF tests only:**
```bash
pytest tests/test_vrfs/test_pedersen/ -v
```

**Ring proof and Ring VRF tests:**
```bash
pytest tests/test_vrfs/test_ring_proof/ tests/test_vrfs/test_ring_vrf/ -v
```

**Hash-to-curve tests:**
```bash
pytest tests/test_h2c_suites/ -v
```

### Run Specific Test Files

**Test a specific curve (e.g., P-256 IETF VRF):**
```bash
pytest tests/test_vrfs/test_ietf/test_p256_sswu_ietf.py -v
```

**Test a specific hash-to-curve implementation:**
```bash
pytest tests/test_h2c_suites/test_p256_ssw_e2c_ro.py -v
```

### Additional Pytest Options

**Run with detailed output:**
```bash
pytest tests/ -vv
```

**Run with coverage report:**
```bash
pytest tests/ --cov=dot_ring --cov-report=html
```

**Run tests in parallel (requires pytest-xdist):**
```bash
pytest tests/ -n auto
```

**Run only failed tests from last run:**
```bash
pytest tests/ --lf
```

---

## 🎯 Supported Curves

The test suite validates VRF implementations across multiple elliptic curves:

| Curve | Family | Hash-to-Curve Method |   H2C-Suite-Tests | IETF VRF | Pedersen VRF | Ring VRF |
|-------|--------|----------------------|----|----------|--------------|----------|
| **Bandersnatch** | Twisted Edwards | Elligator 2          | ✅    | ✅       | ✅ | ✅ |
| **P-256** | Short Weierstrass | SSWU                 |  ✅   | ✅ | ✅ | ⏳ |
| **P-384** | Short Weierstrass | SSWU                 | ✅    | ✅ | ✅ | ⏳ |
| **P-521** | Short Weierstrass | SSWU                 |  ✅   | ✅   | ✅  | ⏳ |
| **secp256k1** | Short Weierstrass | SSWU                 |  ✅   | ✅ | ✅ | ⏳ |
| **Curve25519** | Montgomery | Elligator 2          | ✅    | ✅  | ✅   | ⏳ |
| **Curve448** | Montgomery | Elligator 2          |  ✅   | ✅  | ✅   | ⏳ |
| **Ed25519** | Twisted Edwards | Elligator 2 & TAI    | ✅    | ✅   | ✅   | ⏳ |
| **Ed448** | Twisted Edwards | Elligator 2          |   ✅  | ✅   | ✅   | ⏳ |
|**JubJub** | Twisted Edwards | TAI                  |   ✅  | ✅   | ✅  | ⏳ |
|**BabyJubJub** | Twisted Edwards | TAI                  |  ✅   | ⏳ | ⏳ | ⏳ |

✅ = Implemented and tested | ⏳ = Planned/In progress

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
