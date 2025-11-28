![alt text](https://raw.githubusercontent.com/Chainscore/dot-ring/refs/heads/main/docs/cover.svg)

[![Tests](https://github.com/Chainscore/dot-ring/actions/workflows/test.yml/badge.svg)](https://github.com/Chainscore/dot-ring/actions/workflows/test.yml)
[![codecov](https://codecov.io/gh/Chainscore/dot-ring/branch/main/graph/badge.svg)](https://codecov.io/gh/Chainscore/dot-ring)
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

`dot-ring` is a Python library for Verifiable Random Functions with Additional Data (VRF-AD) supporting 10+ elliptic curves, including IETF VRF, Pedersen VRF, and Ring VRF.

**Specifications:**
[Bandersnatch VRF](https://github.com/davxy/bandersnatch-vrf-spec) •
[Ring Proof](https://github.com/davxy/ring-proof-spec) •
[RFC9381](https://datatracker.ietf.org/doc/rfc9381) •
[RFC9380](https://datatracker.ietf.org/doc/rfc9380)

---

## Installation

### Install from PyPI (Recommended)

Pre-built wheels are available for Linux and macOS - no build tools required:

```bash
pip install dot-ring
```

### Development Setup

For building from source, you need system dependencies:

| OS | Command |
|----|---------|
| **macOS** | `brew install swig` |
| **Ubuntu/Debian** | `sudo apt install swig build-essential` |
| **Fedora/RHEL** | `sudo dnf install swig gcc-c++` |
| **Arch** | `sudo pacman -S swig base-devel` |

Then install in development mode:

```bash
git clone https://github.com/chainscore/dot-ring.git
cd dot-ring
pip install -e .[dev]
```

---

## Usage

```python
secret_key = "3d6406500d4009fdf2604546093665911e753f2213570a29521fd88bc30ede18"
alpha = b"input data"
ad = b"additional data"
```

### IETF VRF

```python
from dot_ring import Bandersnatch, IETF_VRF

# Generate proof
proof = IETF_VRF[Bandersnatch].prove(alpha, secret_key, ad)

# Verify
public_key = IETF_VRF[Bandersnatch].get_public_key(secret_key)
is_valid = proof.verify(public_key, alpha, ad)

# Serialize
proof_bytes = proof.to_bytes()
proof = IETF_VRF[Bandersnatch].from_bytes(proof_bytes)
```

### Pedersen VRF

```python
from dot_ring import Bandersnatch, PedersenVRF

# Generate proof (public key is blinded in proof)
proof = PedersenVRF[Bandersnatch].prove(alpha, secret_key, ad)

# Verify
is_valid = proof.verify(alpha, ad)
```

### Ring VRF

```python
from dot_ring import Bandersnatch, RingVRF

# Setup ring
ring_pks = [pk1, pk2, pk3, ...]  # list of public keys
ring_root = RingVRF[Bandersnatch].construct_ring_root(ring_pks)

# Generate proof
my_pk = RingVRF[Bandersnatch].get_public_key(secret_key)
proof = RingVRF[Bandersnatch].prove(alpha, ad, secret_key, my_pk, ring_pks)

# Verify (proves membership without revealing which key)
is_valid = proof.verify(alpha, ad, ring_root)
```

---

## Testing

```bash
pytest tests/
```

See [TESTING.md](./TESTING.md) for details.

---

## Docker

```bash
docker build -t dot-ring .
docker run -it dot-ring pytest tests/
```

---

## Troubleshooting

| Error | Solution |
|-------|----------|
| `swig: command not found` | Only needed for building from source. Install: `brew install swig` / `apt install swig` |
| `gcc failed` | Only needed for building from source. Install: `xcode-select --install` / `apt install build-essential` |
| Import errors | Try: `pip install dot-ring --force-reinstall --no-cache-dir` |

---

## Contact

**Prasad // Chainscore Labs**

![alt text](https://raw.githubusercontent.com/Chainscore/dot-ring/refs/heads/main/docs/chainscore.png)

[Email](mailto:prasad@chainscore.finance) • [Website](https://chainscore.finance)
