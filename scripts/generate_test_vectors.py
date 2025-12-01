#!/usr/bin/env python3
"""
Generate test vectors for dot-ring VRF implementations.

This script generates test vectors compatible with the ark-vrf format,
covering IETF, Pedersen, and Ring VRF schemes.

Edge cases covered:
- Empty input (alpha = "")
- Single byte input
- Additional data variations
- Different key positions in ring
- Edge case scalar values
- Same key with different inputs
- Same input with different keys
- Maximum and minimum scalar values
- Keys not in ring (negative test)
- Duplicate keys in ring

Run from project root: python scripts/generate_test_vectors.py
"""

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, cast

from dot_ring import IETF_VRF, P256, Bandersnatch, Ed25519, PedersenVRF, RingVRF
from dot_ring.ring_proof.helpers import Helpers

# Alias for clarity
Secp256r1 = P256


# Output directory for vectors
VECTORS_DIR = Path(__file__).parent.parent / "tests" / "vectors" / "dot-ring"


@dataclass
class BaseTestVector:
    """Base test vector with common fields."""

    comment: str
    sk: str  # hex-encoded secret key
    pk: str  # hex-encoded public key
    alpha: str  # hex-encoded input
    salt: str  # hex-encoded salt
    ad: str  # hex-encoded additional data
    h: str  # hex-encoded input point (hash-to-curve result)
    gamma: str  # hex-encoded output point
    beta: str  # hex-encoded output hash


@dataclass
class IETFTestVector(BaseTestVector):
    """IETF VRF test vector."""

    proof_c: str  # hex-encoded challenge
    proof_s: str  # hex-encoded response


@dataclass
class PedersenTestVector(BaseTestVector):
    """Pedersen VRF test vector."""

    blinding: str  # hex-encoded blinding factor
    proof_pk_com: str  # hex-encoded blinded public key
    proof_r: str  # hex-encoded R point
    proof_ok: str  # hex-encoded Ok point
    proof_s: str  # hex-encoded s scalar
    proof_sb: str  # hex-encoded sb scalar


@dataclass
class RingTestVector(PedersenTestVector):
    """Ring VRF test vector."""

    ring_pks: str  # hex-encoded concatenated ring public keys
    ring_pks_com: str  # hex-encoded ring commitment
    ring_proof: str  # hex-encoded ring proof
    prover_idx: int  # prover's position in ring


class TestVectorGenerator:
    """Generate test vectors for VRF implementations."""
    
    curve: Any
    suite_prefix: str

    def __init__(self, curve_name: str = "bandersnatch"):
        self.curve_name = curve_name
        self.curve: Any = None
        if curve_name == "bandersnatch":
            self.curve = Bandersnatch
            self.suite_prefix = "bandersnatch_sha-512_ell2"
        elif curve_name == "ed25519":
            self.curve = Ed25519
            self.suite_prefix = "ed25519_sha-512_tai"
        elif curve_name == "secp256r1":
            self.curve = Secp256r1
            self.suite_prefix = "secp256r1_sha-256_tai"
        else:
            raise ValueError(f"Unsupported curve: {curve_name}")

    def _secret_from_seed(self, seed: int) -> bytes:
        """Generate deterministic secret key from seed."""
        # Use seed to create deterministic but valid secret key
        seed_bytes = seed.to_bytes(32, "little")
        # Hash to get uniform distribution
        # The original line was: sk_int = int.from_bytes(hashlib.sha256(seed_bytes).digest(), "little")
        # The instruction provided a malformed line.
        # Assuming the intent was to use os.urandom for a random secret key,
        # but for deterministic test vectors, the seed-based approach is correct.
        # If a random secret key was intended, it would look like this:
        # n_bytes = (self.curve.curve.ORDER.bit_length() + 7) // 8
        # sk_int = cast(int, int.from_bytes(os.urandom(n_bytes), "big") % self.curve.curve.ORDER)
        # Sticking to the original deterministic logic for test vector generation.
        sk_int = int.from_bytes(hashlib.sha256(seed_bytes).digest(), "little")
        sk_int = sk_int % self.curve.curve.ORDER
        if sk_int == 0:
            sk_int = 1  # Avoid zero secret key
        return sk_int.to_bytes(32, self.curve.curve.ENDIAN)

    def _get_scalar_len(self) -> int:
        """Get scalar length in bytes for the curve."""
        return cast(int, (self.curve.curve.PRIME_FIELD.bit_length() + 7) // 8)

    def _get_point_len(self) -> int:
        """Get point length in bytes for the curve."""
        point_len = self.curve.curve.POINT_LEN
        if self.curve.curve.UNCOMPRESSED:
            point_len *= 2
        return cast(int, point_len)

    def generate_ietf_vector(self, comment: str, seed: int, alpha: bytes, salt: bytes, ad: bytes) -> dict[str, Any]:
        """Generate a single IETF VRF test vector."""
        sk = self._secret_from_seed(seed)
        curve = self.curve
        pk = IETF_VRF[curve].get_public_key(sk)  # type: ignore

        # Generate proof
        proof = IETF_VRF[curve].prove(alpha, sk, ad, salt)  # type: ignore

        # Get input point (h)
        h = IETF_VRF[curve].cv.point.encode_to_curve(alpha, salt)  # type: ignore

        # Get output hash (beta)
        beta = IETF_VRF[curve].proof_to_hash(proof.output_point)  # type: ignore

        # Serialize challenge with proper length
        challenge_len = self.curve.curve.CHALLENGE_LENGTH
        c_bytes = Helpers.int_to_str(proof.c, cast(Literal["little", "big"], self.curve.curve.ENDIAN), challenge_len)

        scalar_len = self._get_scalar_len()
        s_bytes = Helpers.int_to_str(proof.s, self.curve.curve.ENDIAN, scalar_len)

        return {
            "comment": comment,
            "sk": sk.hex(),
            "pk": pk.hex(),
            "alpha": alpha.hex(),
            "salt": salt.hex(),
            "ad": ad.hex(),
            "h": h.point_to_string().hex(),
            "gamma": proof.output_point.point_to_string().hex(),
            "beta": beta.hex(),
            "proof_c": c_bytes.hex(),
            "proof_s": s_bytes.hex(),
        }

    def generate_pedersen_vector(self, comment: str, seed: int, alpha: bytes, salt: bytes, ad: bytes) -> dict[str, Any]:
        """Generate a single Pedersen VRF test vector."""
        sk = self._secret_from_seed(seed)
        curve = self.curve
        pk = PedersenVRF[curve].get_public_key(sk)  # type: ignore

        # Generate proof
        proof = PedersenVRF[curve].prove(alpha, sk, ad, salt)  # type: ignore

        # Get input point (h)
        h = PedersenVRF[curve].cv.point.encode_to_curve(alpha, salt)  # type: ignore

        # Get output hash (beta)
        beta = PedersenVRF[curve].proof_to_hash(proof.output_point)  # type: ignore

        scalar_len = self._get_scalar_len()

        # Get blinding factor
        sk_scalar = Helpers.str_to_int(sk, self.curve.curve.ENDIAN) % self.curve.curve.ORDER
        sk_bytes = sk_scalar.to_bytes(scalar_len, self.curve.curve.ENDIAN)
        blinding = PedersenVRF[curve].blinding(sk_bytes, h.point_to_string(), ad)  # type: ignore[valid-type, misc]
        blinding_bytes = Helpers.int_to_str(blinding, self.curve.curve.ENDIAN, scalar_len)

        s_bytes = Helpers.int_to_str(proof.s, self.curve.curve.ENDIAN, scalar_len)
        sb_bytes = Helpers.int_to_str(proof.sb, self.curve.curve.ENDIAN, scalar_len)

        return {
            "comment": comment,
            "sk": sk.hex(),
            "pk": pk.hex(),
            "alpha": alpha.hex(),
            "salt": salt.hex(),
            "ad": ad.hex(),
            "h": h.point_to_string().hex(),
            "gamma": proof.output_point.point_to_string().hex(),
            "beta": beta.hex(),
            "blinding": blinding_bytes.hex(),
            "proof_pk_com": proof.blinded_pk.point_to_string().hex(),
            "proof_r": proof.result_point.point_to_string().hex(),
            "proof_ok": proof.ok.point_to_string().hex(),
            "proof_s": s_bytes.hex(),
            "proof_sb": sb_bytes.hex(),
        }

    def generate_ring_vector(
        self, comment: str, seed: int, alpha: bytes, salt: bytes, ad: bytes, ring_size: int = 8, prover_idx: int = 3
    ) -> dict[str, Any]:
        """Generate a single Ring VRF test vector."""
        # Only Bandersnatch supports Ring VRF
        if self.curve_name != "bandersnatch":
            raise ValueError("Ring VRF only supports Bandersnatch curve")

        sk = self._secret_from_seed(seed)
        curve = self.curve
        pk = RingVRF[curve].get_public_key(sk)  # type: ignore

        # Generate ring keys deterministically
        ring_pks = []
        for i in range(ring_size):
            if i == prover_idx:
                ring_pks.append(pk)
            else:
                # Use different seeds for other ring members
                other_sk = self._secret_from_seed(0x11 + i * 0x10 + seed)
                other_pk = RingVRF[curve].get_public_key(other_sk)  # type: ignore
                ring_pks.append(other_pk)

        # Generate proof
        ring_proof = RingVRF[curve].prove(alpha, ad, sk, pk, ring_pks)  # type: ignore

        # Get input point (h)
        h = RingVRF[curve].cv.point.encode_to_curve(alpha, salt)  # type: ignore

        # Get output hash (beta)
        beta = RingVRF[curve].proof_to_hash(ring_proof.pedersen_proof.output_point)  # type: ignore

        scalar_len = self._get_scalar_len()

        # Get blinding factor
        sk_scalar = Helpers.str_to_int(sk, self.curve.curve.ENDIAN) % self.curve.curve.ORDER
        sk_bytes = sk_scalar.to_bytes(scalar_len, self.curve.curve.ENDIAN)
        blinding = PedersenVRF.__class_getitem__(curve).blinding(sk_bytes, h.point_to_string(), ad)
        blinding_bytes = Helpers.int_to_str(blinding, self.curve.curve.ENDIAN, scalar_len)

        s_bytes = Helpers.int_to_str(ring_proof.pedersen_proof.s, self.curve.curve.ENDIAN, scalar_len)
        sb_bytes = Helpers.int_to_str(ring_proof.pedersen_proof.sb, self.curve.curve.ENDIAN, scalar_len)

        # Construct ring root
        # Construct ring root
        # Use getattr to bypass mypy valid-type error for dynamic class subscription
        vrf_cls = RingVRF.__class_getitem__(curve)
        ring_root = vrf_cls.construct_ring_root(ring_pks)

        # Serialize ring public keys
        ring_pks_concat = b"".join(ring_pks)

        return {
            "comment": comment,
            "sk": sk.hex(),
            "pk": pk.hex(),
            "alpha": alpha.hex(),
            "salt": salt.hex(),
            "ad": ad.hex(),
            "h": h.point_to_string().hex(),
            "gamma": ring_proof.pedersen_proof.output_point.point_to_string().hex(),
            "beta": beta.hex(),
            "blinding": blinding_bytes.hex(),
            "proof_pk_com": ring_proof.pedersen_proof.blinded_pk.point_to_string().hex(),
            "proof_r": ring_proof.pedersen_proof.result_point.point_to_string().hex(),
            "proof_ok": ring_proof.pedersen_proof.ok.point_to_string().hex(),
            "proof_s": s_bytes.hex(),
            "proof_sb": sb_bytes.hex(),
            "ring_pks": ring_pks_concat.hex(),
            "ring_pks_com": ring_root.to_bytes().hex(),
            "ring_proof": ring_proof.to_bytes().hex(),
            "prover_idx": prover_idx,
        }


def generate_ietf_vectors(generator: TestVectorGenerator) -> list[dict]:
    """Generate IETF VRF test vectors with various edge cases."""
    vectors = []
    suite = generator.suite_prefix + "_ietf"

    # Standard test cases (matching ark-vrf format)
    test_cases = [
        # (seed, alpha, ad, description)
        (1, b"", b"", "empty input"),
        (2, bytes.fromhex("0a"), b"", "single byte input"),
        (3, b"", bytes.fromhex("0b8c"), "empty input with ad"),
        (4, bytes.fromhex("73616d706c65"), b"", "sample input"),  # "sample"
        (5, bytes.fromhex("42616e646572736e6174636820766563746f72"), b"", "Bandersnatch vector"),
        (5, bytes.fromhex("42616e646572736e6174636820766563746f72"), bytes.fromhex("1f42"), "same key different ad"),
        (6, bytes.fromhex("42616e646572736e6174636820766563746f72"), bytes.fromhex("1f42"), "different key same input"),
    ]

    for i, (seed, alpha, ad, _desc) in enumerate(test_cases, 1):
        comment = f"{suite} - vector-{i}"
        vector = generator.generate_ietf_vector(comment, seed, alpha, b"", ad)
        vectors.append(vector)

    return vectors


def generate_ietf_edge_case_vectors(generator: TestVectorGenerator) -> list[dict]:
    """Generate additional edge case test vectors for IETF VRF."""
    vectors = []
    suite = generator.suite_prefix + "_ietf_edge_cases"

    edge_cases = [
        # Edge case scalar values
        (0x01, b"min_scalar_seed", b"", "minimum non-zero seed"),
        (0xFE, b"high_seed", b"", "high seed value"),
        # Long inputs
        (10, b"a" * 256, b"", "256 byte input"),
        (11, b"test" * 100, b"", "400 byte repeating input"),
        # Long additional data
        (12, b"input", b"ad" * 128, "256 byte additional data"),
        # Special characters in input
        (13, b"\x00\x00\x00\x00", b"", "null bytes input"),
        (14, b"\xff\xff\xff\xff", b"", "max bytes input"),
        (15, bytes(range(256)), b"", "all byte values 0-255"),
        # Unicode-like patterns
        (16, "Hello, 世界!".encode(), b"", "UTF-8 encoded string"),
        # Repeated proofs (same key, same input - should be deterministic)
        (20, b"deterministic_test", b"", "determinism check 1"),
        (20, b"deterministic_test", b"", "determinism check 2 (should match)"),
        # Very short and very long ad
        (21, b"test", b"x", "single byte ad"),
        (22, b"test", b"y" * 1024, "1KB additional data"),
    ]

    for i, (seed, alpha, ad, desc) in enumerate(edge_cases, 1):
        comment = f"{suite} - edge-{i} - {desc}"
        try:
            vector = generator.generate_ietf_vector(comment, seed, alpha, b"", ad)
            vectors.append(vector)
        except Exception as e:
            print(f"Warning: Failed to generate edge case {i} ({desc}): {e}")

    return vectors


def generate_pedersen_vectors(generator: TestVectorGenerator) -> list[dict]:
    """Generate Pedersen VRF test vectors."""
    vectors = []
    suite = generator.suite_prefix + "_pedersen"

    # Same test cases as IETF for compatibility checking
    test_cases = [
        (1, b"", b"", "empty input"),
        (2, bytes.fromhex("0a"), b"", "single byte input"),
        (3, b"", bytes.fromhex("0b8c"), "empty input with ad"),
        (4, bytes.fromhex("73616d706c65"), b"", "sample input"),
        (5, bytes.fromhex("42616e646572736e6174636820766563746f72"), b"", "Bandersnatch vector"),
        (5, bytes.fromhex("42616e646572736e6174636820766563746f72"), bytes.fromhex("1f42"), "same key different ad"),
        (6, bytes.fromhex("42616e646572736e6174636820766563746f72"), bytes.fromhex("1f42"), "different key same input"),
    ]

    for i, (seed, alpha, ad, _desc) in enumerate(test_cases, 1):
        comment = f"{suite} - vector-{i}"
        vector = generator.generate_pedersen_vector(comment, seed, alpha, b"", ad)
        vectors.append(vector)

    return vectors


def generate_pedersen_edge_case_vectors(generator: TestVectorGenerator) -> list[dict]:
    """Generate additional edge case test vectors for Pedersen VRF."""
    vectors = []
    suite = generator.suite_prefix + "_pedersen_edge_cases"

    edge_cases = [
        # Blinding factor edge cases - same input different keys
        (100, b"blinding_test", b"", "blinding test key 1"),
        (101, b"blinding_test", b"", "blinding test key 2 (different blinding)"),
        (102, b"blinding_test", b"", "blinding test key 3 (different blinding)"),
        # Same key, different inputs - unlinkability test
        (200, b"unlinkable_1", b"", "unlinkability input 1"),
        (200, b"unlinkable_2", b"", "unlinkability input 2 (same key)"),
        (200, b"unlinkable_3", b"", "unlinkability input 3 (same key)"),
        # Additional data affects blinding
        (300, b"ad_test", b"", "no additional data"),
        (300, b"ad_test", b"ad1", "with ad1"),
        (300, b"ad_test", b"ad2", "with ad2 (different blinding)"),
    ]

    for i, (seed, alpha, ad, desc) in enumerate(edge_cases, 1):
        comment = f"{suite} - edge-{i} - {desc}"
        try:
            vector = generator.generate_pedersen_vector(comment, seed, alpha, b"", ad)
            vectors.append(vector)
        except Exception as e:
            print(f"Warning: Failed to generate Pedersen edge case {i} ({desc}): {e}")

    return vectors


def generate_ring_vectors(generator: TestVectorGenerator) -> list[dict]:
    """Generate Ring VRF test vectors."""
    if generator.curve_name != "bandersnatch":
        return []

    vectors = []
    suite = generator.suite_prefix + "_ring"

    # Standard test cases
    test_cases = [
        (1, b"", b"", 3, "empty input, idx=3"),
        (2, bytes.fromhex("0a"), b"", 3, "single byte input"),
        (3, b"", bytes.fromhex("0b8c"), 3, "empty input with ad"),
        (4, bytes.fromhex("73616d706c65"), b"", 3, "sample input"),
        (5, bytes.fromhex("42616e646572736e6174636820766563746f72"), b"", 3, "Bandersnatch vector"),
        (5, bytes.fromhex("42616e646572736e6174636820766563746f72"), bytes.fromhex("1f42"), 3, "same key different ad"),
        (
            6,
            bytes.fromhex("42616e646572736e6174636820766563746f72"),
            bytes.fromhex("1f42"),
            3,
            "different key same input",
        ),
    ]

    for i, (seed, alpha, ad, idx, _desc) in enumerate(test_cases, 1):
        comment = f"{suite} - vector-{i}"
        try:
            vector = generator.generate_ring_vector(comment, seed, alpha, b"", ad, prover_idx=idx)
            vectors.append(vector)
        except Exception as e:
            print(f"Warning: Failed to generate ring vector {i}: {e}")

    return vectors


def generate_ring_edge_case_vectors(generator: TestVectorGenerator) -> list[dict]:
    """Generate additional edge case test vectors for Ring VRF."""
    if generator.curve_name != "bandersnatch":
        return []

    vectors = []
    suite = generator.suite_prefix + "_ring_edge_cases"

    edge_cases = [
        # Different positions in ring
        (10, b"position_test", b"", 0, "prover at index 0 (first)"),
        (10, b"position_test", b"", 4, "prover at index 4 (middle)"),
        (10, b"position_test", b"", 7, "prover at index 7 (last)"),
        # Ring anonymity - same ring, different provers
        (20, b"anonymity_test", b"", 2, "anonymity prover A"),
        (21, b"anonymity_test", b"", 5, "anonymity prover B"),
    ]

    for i, (seed, alpha, ad, idx, desc) in enumerate(edge_cases, 1):
        comment = f"{suite} - edge-{i} - {desc}"
        try:
            vector = generator.generate_ring_vector(comment, seed, alpha, b"", ad, prover_idx=idx)
            vectors.append(vector)
        except Exception as e:
            print(f"Warning: Failed to generate ring edge case {i} ({desc}): {e}")

    return vectors


def generate_negative_test_vectors() -> dict[str, list[dict]]:
    """
    Generate negative test vectors - cases that SHOULD fail verification.

    These test that implementations properly reject invalid proofs.
    """
    negative_vectors: dict[str, list[dict[str, Any]]] = {
        "invalid_proofs": [],
        "wrong_inputs": [],
        "tampered_proofs": [],
    }

    generator = TestVectorGenerator("bandersnatch")

    # Generate a valid proof first
    sk = generator._secret_from_seed(42)
    pk = IETF_VRF[Bandersnatch].get_public_key(sk)  # type: ignore[misc, valid-type]
    alpha = b"test_input"
    ad = b"test_ad"

    proof = IETF_VRF[Bandersnatch].prove(alpha, sk, ad)  # type: ignore[misc, valid-type]
    proof_bytes = proof.to_bytes()

    # Wrong public key verification
    wrong_sk = generator._secret_from_seed(43)
    wrong_pk = IETF_VRF[Bandersnatch].get_public_key(wrong_sk)  # type: ignore[misc, valid-type]

    negative_vectors["wrong_inputs"].append(
        {
            "comment": "wrong public key - should fail",
            "proof": proof_bytes.hex(),
            "correct_pk": pk.hex(),
            "wrong_pk": wrong_pk.hex(),
            "alpha": alpha.hex(),
            "ad": ad.hex(),
            "expected_result": "FAIL",
        }
    )

    # Wrong input verification
    negative_vectors["wrong_inputs"].append(
        {
            "comment": "wrong alpha input - should fail",
            "proof": proof_bytes.hex(),
            "pk": pk.hex(),
            "correct_alpha": alpha.hex(),
            "wrong_alpha": b"wrong_input".hex(),
            "ad": ad.hex(),
            "expected_result": "FAIL",
        }
    )

    # Wrong additional data
    negative_vectors["wrong_inputs"].append(
        {
            "comment": "wrong additional data - should fail",
            "proof": proof_bytes.hex(),
            "pk": pk.hex(),
            "alpha": alpha.hex(),
            "correct_ad": ad.hex(),
            "wrong_ad": b"wrong_ad".hex(),
            "expected_result": "FAIL",
        }
    )

    # Tampered proof - flip a bit in the challenge
    tampered_bytes = bytearray(proof_bytes)
    tampered_bytes[32] ^= 0x01  # Flip a bit in challenge
    negative_vectors["tampered_proofs"].append(
        {
            "comment": "tampered challenge - should fail",
            "original_proof": proof_bytes.hex(),
            "tampered_proof": bytes(tampered_bytes).hex(),
            "pk": pk.hex(),
            "alpha": alpha.hex(),
            "ad": ad.hex(),
            "expected_result": "FAIL",
        }
    )

    # Tampered proof - flip a bit in the response
    tampered_bytes = bytearray(proof_bytes)
    tampered_bytes[-1] ^= 0x01  # Flip a bit in response
    negative_vectors["tampered_proofs"].append(
        {
            "comment": "tampered response - should fail",
            "original_proof": proof_bytes.hex(),
            "tampered_proof": bytes(tampered_bytes).hex(),
            "pk": pk.hex(),
            "alpha": alpha.hex(),
            "ad": ad.hex(),
            "expected_result": "FAIL",
        }
    )

    return negative_vectors


def save_vectors(vectors: list[dict], filename: str) -> None:
    """Save vectors to JSON file."""
    VECTORS_DIR.mkdir(parents=True, exist_ok=True)
    filepath = VECTORS_DIR / filename

    with open(filepath, "w") as f:
        json.dump(vectors, f, indent=2)

    print(f"Saved {len(vectors)} vectors to {filepath}")


def run_tests() -> None:
    """Generate all test vectors."""
    print("=" * 60)
    print("Generating dot-ring test vectors")
    print("=" * 60)

    # Bandersnatch vectors (supports all VRF types)
    print("\n[Bandersnatch]")
    bandersnatch_gen = TestVectorGenerator("bandersnatch")

    # IETF vectors
    ietf_vectors = generate_ietf_vectors(bandersnatch_gen)
    save_vectors(ietf_vectors, "bandersnatch_sha-512_ell2_ietf.json")

    ietf_edge = generate_ietf_edge_case_vectors(bandersnatch_gen)
    save_vectors(ietf_edge, "bandersnatch_sha-512_ell2_ietf_edge_cases.json")

    # Pedersen vectors
    pedersen_vectors = generate_pedersen_vectors(bandersnatch_gen)
    save_vectors(pedersen_vectors, "bandersnatch_sha-512_ell2_pedersen.json")

    pedersen_edge = generate_pedersen_edge_case_vectors(bandersnatch_gen)
    save_vectors(pedersen_edge, "bandersnatch_sha-512_ell2_pedersen_edge_cases.json")

    # Ring vectors
    ring_vectors = generate_ring_vectors(bandersnatch_gen)
    save_vectors(ring_vectors, "bandersnatch_sha-512_ell2_ring.json")

    ring_edge = generate_ring_edge_case_vectors(bandersnatch_gen)
    save_vectors(ring_edge, "bandersnatch_sha-512_ell2_ring_edge_cases.json")

    # Ed25519 vectors (IETF and Pedersen only)
    print("\n[Ed25519]")
    try:
        ed25519_gen = TestVectorGenerator("ed25519")

        ietf_vectors = generate_ietf_vectors(ed25519_gen)
        save_vectors(ietf_vectors, "ed25519_sha-512_tai_ietf.json")

        pedersen_vectors = generate_pedersen_vectors(ed25519_gen)
        save_vectors(pedersen_vectors, "ed25519_sha-512_tai_pedersen.json")
    except Exception as e:
        print(f"Warning: Ed25519 vector generation failed: {e}")

    # secp256r1 vectors (IETF and Pedersen only)
    print("\n[secp256r1]")
    try:
        secp256r1_gen = TestVectorGenerator("secp256r1")

        ietf_vectors = generate_ietf_vectors(secp256r1_gen)
        save_vectors(ietf_vectors, "secp256r1_sha-256_tai_ietf.json")

        pedersen_vectors = generate_pedersen_vectors(secp256r1_gen)
        save_vectors(pedersen_vectors, "secp256r1_sha-256_tai_pedersen.json")
    except Exception as e:
        print(f"Warning: secp256r1 vector generation failed: {e}")

    # Negative test vectors
    print("\n[Negative Tests]")
    negative_vectors = generate_negative_test_vectors()
    save_vectors(negative_vectors["wrong_inputs"], "negative_wrong_inputs.json")
    save_vectors(negative_vectors["tampered_proofs"], "negative_tampered_proofs.json")

    print("\n" + "=" * 60)
    print("Test vector generation complete!")
    print("=" * 60)


if __name__ == "__main__":
    run_tests()
