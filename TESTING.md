# Testing Guide

This project comes with a comprehensive test suite to validate the correctness and security of all implemented primitives.  
All unit and integration tests are located under the [`tests/`](./tests) directory.

---

## 📂 Test Structure

Below is an overview of the test files and their purposes:


- **`test_all_vrfs.py`**  
  Generates a sample signature for each implemented VRF and verifies whether it is valid.  
  Ensures VRF correctness across different implementations.

- **`test_e2c.py`**  
  Validates the **Encode-to-Curve (E2C)** function.  
  This function takes raw input data and maps it to a valid Bandersnatch curve point,  
  which is then used as the VRF input point.

- **`test_ietf.py`**  
  Tests the implementation against **official IETF VRF test vectors** provided here:  
  [Bandersnatch VRF Spec Vectors](https://github.com/davxy/bandersnatch-vrf-spec/tree/main/assets/vectors).  
  Ensures compliance with the standard.

- **`test_pedersen.py`**  
  Covers **official Pedersen VRF test vectors** for, checking correctness of commitment generation and verification.

- **`test_ring_proof.py`**  
  Validates **Ring Proofs**, including acceptance of `pk_ring` and correctness of verification logic.

- **`test_ring_vrf.py`**  
  Tests the **official Ring VRF test vectors** for correctness of construction, signing, and verification.

---

## ▶️ Running the Tests

The tests are written using **pytest**.  
You can run the entire suite or individual files as follows:

- Run all tests:
```bash
pytest tests/
```
-Run a specific test file (e.g., Pedersen VRF tests):
```
pytest tests/test_pedersen.py -v
```
