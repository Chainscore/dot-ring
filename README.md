![alt text](./docs/cover.svg)

[![Tests](https://github.com/Chainscore/dot-ring/actions/workflows/test.yml/badge.svg)](https://github.com/Chainscore/dot-ring/actions/workflows/test.yml)
[![codecov](https://codecov.io/gh/Chainscore/dot-ring/branch/main/graph/badge.svg)](https://codecov.io/gh/Chainscore/dot-ring)
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

`@dot-ring` is a Python library for generating Verifiable Random Functions with Additional Data (VRF-AD) on 10+ Elliptic Curves, including IETF, Pedersen VRF and Ring Proof.


Specifications in compliance: 
- [Bandersnatch VRF](https://github.com/davxy/bandersnatch-vrf-spec/blob/main/specification.md) 
- [Ring Proof](https://github.com/davxy/ring-proof-spec)
- [RFC9381](https://datatracker.ietf.org/doc/rfc9381)
- [RFC9380](https://datatracker.ietf.org/doc/rfc9380)
- [BCGSV23](https://eprint.iacr.org/2023/002)
- [MSZ21](https://eprint.iacr.org/2021/1152)
---

## Installation & Setup - ⚠️ WIP

### Prerequisites
- Python 3.12 or higher
- Install [`blst`](https://github.com/supranational/blst): High-performance MSM (Multi Scalar Multiplication)

###  Clone and install the library

```bash
git clone https://github.com/chainscore/dot-ring.git
cd dot-ring
pip install .
```

## Example Usage
```python
#sample test vector
secret_key="3d6406500d4009fdf2604546093665911e753f2213570a29521fd88bc30ede18"
alpha=""
salt=""
add=""
ring_pks="7b32d917d5aa771d493c47b0e096886827cd056c82dbdba19e60baa8b2c60313d3b1bdb321123449c6e89d310bc6b7f654315eb471c84778353ce08b951ad471561fdb0dcfb8bd443718b942f82fe717238cbcf8d12b8d22861c8a09a984a3c5a1b1da71cc4682e159b7da23050d8b6261eb11a3247c89b07ef56ccd002fd38b4fd11f89c2a1aaefe856bb1c5d4a1fad73f4de5e41804ca2c17ba26d6e10050c86d06ee2c70da6cf2da2a828d8a9d8ef755ad6e580e838359a10accb086ae437ad6fdeda0dde0a57c51d3226b87e3795e6474393772da46101fd597fbd456c1b3f9dc0c4f67f207974123830c2d66988fb3fb44becbbba5a64143f376edc51d9"

```
### For IETF VRF
```python
from dot_ring.curve.specs.bandersnatch import BandersnatchPoint, Bandersnatch_TE_Curve
from dot_ring.vrf.ietf.ietf import IETF_VRF

curve = Bandersnatch_TE_Curve
point_type = BandersnatchPoint

vrf = IETF_VRF(curve, point_type)


public_key = point_type.string_to_point(rvrf.get_public_key(secret_key))
input_point = point_type.encode_to_curve(alpha, salt)
proof = vrf.proof(alpha, secret_key, add)  # Generates Proof of length 96 bytes
is_valid = vrf.verify(public_key, input_point, add, proof)
```

### For Pedersen VRF
```python
from dot_ring.vrf.ietf.pedersen import PedersenVRF
from dot_ring.curve.specs.bandersnatch import BandersnatchPoint, Bandersnatch_TE_Curve

curve = Bandersnatch_TE_Curve
point_type = BandersnatchPoint

vrf = PedersenVRF(curve, point_type)

# Public key is not exposed by definition in Pedersen VRF
input_point = point_type.encode_to_curve(alpha, salt)
proof = vrf.proof(alpha, secret_key, add)  # Generates Proof of length 192 bytes
is_valid = vrf.verify(input_point, add, proof)
```
### For Ring VRF
```python
from dot_ring.vrf.ring.ring_vrf import RingVrf

rvrf = RingVrf()
# Generate ring root commitment
ring_root = rvrf.construct_ring_root(ring_pks, third_party_msm=True/False)  # generate ring root of length 144 bytes
# Generate Ring VRF proof
public_key = vrf.get_public_key(secret_key)
ring_vrf_proof = rvrf.ring_vrf_proof(alpha,add,secret_key,public_key,ring_pks,third_party_msm=True/False)  # Generates proof of length 784 bytes
#verfiy Ring VRF Proof
is_valid = rvrf.ring_vrf_proof_verify(add,ring_root,ring_vrf_proof, alpha)
```


## Note: Third-Party MSM
To use third-party MSM optimizations in the KZG commitment (i.e., third_party_msm=True), you must install blst, which provides efficient multi-scalar multiplication support.
### (Optional) Enable third-party MSM with blst
To use third_party_msm=True (for fast multi-scalar multiplication):
Clone it from [here](https://github.com/supranational/blst)
```bash
git clone https://github.com/supranational/blst.git
cd blst/bindings/python
./run.me
```

## Testing

You can run the test suite with **pytest**:

```bash
pytest tests/
```
See [TESTING.md](./TESTING.md) for an overview of the test suite and instructions on running tests.


## 🐳 Docker Setup

The following commands guide you through building the image, running tests, generating coverage reports, and accessing an interactive shell.

### Build the Docker Image
```bash
docker build -t dot_ring .
```

### Run tests inside a container
```bash
docker run -it dot_ring pytest tests/
```

### Generate a Coverage report
- Terminal summary
```bash
docker run -it dot_ring pytest tests/ --cov=dot_ring --cov-report=term-missing
```

- HTML report
```bash
docker run -it dot_ring pytest tests/ --cov=dot_ring --cov-report=html
open htmlcov/index.html #open it in your browser
``` 
Access an interactive shell inside the container
```bash
docker run -it dot_ring bash

```

## Contact

prasad@chainscore.finance