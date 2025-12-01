"""
dot-ring: A Python library for Verifiable Random Functions with Additional Data (VRF-AD).

Supports 10+ elliptic curves including IETF, Pedersen VRF and Ring Proof.

Example usage:
    >>> from dot_ring import Bandersnatch, IETF_VRF, PedersenVRF, RingVRF
    >>>
    >>> # IETF VRF
    >>> proof = IETF_VRF[Bandersnatch].prove(alpha, secret_key, additional_data)
    >>> is_valid = proof.verify(public_key, alpha, additional_data)
    >>>
    >>> # Pedersen VRF
    >>> proof = PedersenVRF[Bandersnatch].prove(alpha, secret_key, additional_data)
    >>> is_valid = proof.verify(alpha, additional_data)
    >>>
    >>> # Ring VRF
    >>> ring_root = RingVRF[Bandersnatch].construct_ring_root(keys_list)
    >>> proof = RingVRF[Bandersnatch].prove(alpha, ad, secret_key, producer_key, keys)
    >>> is_valid = proof.verify(alpha, ad, ring_root)
"""

__version__ = "0.1.0"

# =============================================================================
# VRF Implementations
# =============================================================================
# ZK-friendly curves
from dot_ring.curve.specs.baby_jubjub import BabyJubJub

# =============================================================================
# Curve Variants - Primary curves
# =============================================================================
from dot_ring.curve.specs.bandersnatch import Bandersnatch
from dot_ring.curve.specs.bandersnatch_sw import Bandersnatch_SW

# BLS12-381 curves
from dot_ring.curve.specs.bls12_381_G1 import BLS12_381_G1_NU, BLS12_381_G1_RO
from dot_ring.curve.specs.bls12_381_G2 import BLS12_381_G2_NU, BLS12_381_G2_RO
from dot_ring.curve.specs.curve448 import Curve448_NU, Curve448_RO
from dot_ring.curve.specs.curve25519 import Curve25519_NU, Curve25519_RO
from dot_ring.curve.specs.ed448 import Ed448_NU, Ed448_RO
from dot_ring.curve.specs.ed25519 import Ed25519_NU, Ed25519_RO
from dot_ring.curve.specs.jubjub import JubJub

# NIST curves
from dot_ring.curve.specs.p256 import P256_NU, P256_RO
from dot_ring.curve.specs.p384 import P384_NU, P384_RO
from dot_ring.curve.specs.p521 import P521_NU, P521_RO
from dot_ring.curve.specs.secp256k1 import Secp256k1_NU, Secp256k1_RO
from dot_ring.vrf.ietf.ietf import IETF_VRF
from dot_ring.vrf.pedersen.pedersen import PedersenVRF
from dot_ring.vrf.ring.ring_vrf import RingVRF

# =============================================================================
# Convenience aliases
# =============================================================================
Ed25519 = Ed25519_RO
Ed448 = Ed448_RO
Curve25519 = Curve25519_RO
Curve448 = Curve448_RO
P256 = P256_RO
P384 = P384_RO
P521 = P521_RO
Secp256k1 = Secp256k1_RO
BLS12_381_G1 = BLS12_381_G1_RO
BLS12_381_G2 = BLS12_381_G2_RO

# =============================================================================
# Public API
# =============================================================================
__all__ = [
    # Version
    "__version__",
    # VRF implementations
    "IETF_VRF",
    "PedersenVRF",
    "RingVRF",
    # Primary curves
    "Bandersnatch",
    "Bandersnatch_SW",
    "Ed25519",
    "Ed25519_RO",
    "Ed25519_NU",
    "Ed448",
    "Ed448_RO",
    "Ed448_NU",
    "Curve25519",
    "Curve25519_RO",
    "Curve25519_NU",
    "Curve448",
    "Curve448_RO",
    "Curve448_NU",
    # NIST curves
    "P256",
    "P256_RO",
    "P256_NU",
    "P384",
    "P384_RO",
    "P384_NU",
    "P521",
    "P521_RO",
    "P521_NU",
    "Secp256k1",
    "Secp256k1_RO",
    "Secp256k1_NU",
    # ZK-friendly curves
    "BabyJubJub",
    "JubJub",
    # BLS12-381
    "BLS12_381_G1",
    "BLS12_381_G1_RO",
    "BLS12_381_G1_NU",
    "BLS12_381_G2",
    "BLS12_381_G2_RO",
    "BLS12_381_G2_NU",
]
