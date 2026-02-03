#!/usr/bin/env python3
import json
from pathlib import Path
from typing import Any

import pytest

from dot_ring import IETF_VRF, P256, Bandersnatch, Ed25519, PedersenVRF, RingVRF
from dot_ring.ring_proof.helpers import Helpers

# Alias
Secp256r1 = P256

VECTORS_DIR = Path(__file__).parent / "vectors" / "dot-ring"


# =============================================================================
# Fixtures for loading test vectors
# =============================================================================


def load_vectors(filename: str) -> list[dict[str, Any]]:
    """Load test vectors from JSON file."""
    filepath = VECTORS_DIR / filename
    if not filepath.exists():
        pytest.skip(f"Vector file not found: {filepath}")
    with open(filepath) as f:
        return json.load(f)


def get_vector_ids(vectors: list[dict]) -> list[str]:
    """Extract vector IDs for pytest parametrization."""
    return [v.get("comment", f"vector-{i}") for i, v in enumerate(vectors)]


# =============================================================================
# IETF VRF Tests
# =============================================================================


class TestIETFVRF:
    """Test suite for IETF VRF test vectors."""

    @staticmethod
    def verify_ietf_vector(vector: dict[str, Any], curve) -> None:
        """Verify a single IETF VRF test vector."""
        # Parse inputs
        sk = bytes.fromhex(vector["sk"])
        pk = bytes.fromhex(vector["pk"])
        alpha = bytes.fromhex(vector["alpha"])
        salt = bytes.fromhex(vector["salt"]) if vector.get("salt") else b""
        ad = bytes.fromhex(vector["ad"]) if vector.get("ad") else b""
        expected_gamma = bytes.fromhex(vector["gamma"])
        expected_beta = bytes.fromhex(vector["beta"])
        expected_c = bytes.fromhex(vector["proof_c"])
        expected_s = bytes.fromhex(vector["proof_s"])

        # Generate proof
        proof = IETF_VRF[curve].prove(alpha, sk, ad, salt)

        # Verify output point matches
        gamma_bytes = proof.output_point.point_to_string()
        assert gamma_bytes == expected_gamma, f"gamma mismatch: expected {expected_gamma.hex()}, got {gamma_bytes.hex()}"

        # Verify proof challenge
        challenge_len = curve.curve.CHALLENGE_LENGTH
        c_bytes = Helpers.int_to_str(proof.c, curve.curve.ENDIAN, challenge_len)
        assert c_bytes == expected_c, f"challenge mismatch: expected {expected_c.hex()}, got {c_bytes.hex()}"

        # Verify proof response
        scalar_len = (curve.curve.PRIME_FIELD.bit_length() + 7) // 8
        s_bytes = Helpers.int_to_str(proof.s, curve.curve.ENDIAN, scalar_len)
        assert s_bytes == expected_s, f"response mismatch: expected {expected_s.hex()}, got {s_bytes.hex()}"

        # Verify the proof
        assert proof.verify(pk, alpha, ad, salt), "Proof verification failed"

        # Verify output hash
        beta = IETF_VRF[curve].proof_to_hash(proof.output_point)
        assert beta == expected_beta, f"beta mismatch: expected {expected_beta.hex()}, got {beta.hex()}"


# Bandersnatch IETF vectors
@pytest.fixture(scope="module")
def bandersnatch_ietf_vectors():
    return load_vectors("bandersnatch_sha-512_ell2_ietf.json")


@pytest.fixture(scope="module")
def bandersnatch_ietf_edge_vectors():
    return load_vectors("bandersnatch_sha-512_ell2_ietf_edge_cases.json")


class TestBandersnatchIETF(TestIETFVRF):
    """Bandersnatch IETF VRF test vectors."""

    def test_vectors(self, bandersnatch_ietf_vectors):
        """Test standard IETF vectors."""
        for vector in bandersnatch_ietf_vectors:
            self.verify_ietf_vector(vector, Bandersnatch)

    def test_edge_case_vectors(self, bandersnatch_ietf_edge_vectors):
        """Test edge case IETF vectors."""
        for vector in bandersnatch_ietf_edge_vectors:
            self.verify_ietf_vector(vector, Bandersnatch)


# Ed25519 IETF vectors
@pytest.fixture(scope="module")
def ed25519_ietf_vectors():
    return load_vectors("ed25519_sha-512_tai_ietf.json")


class TestEd25519IETF(TestIETFVRF):
    """Ed25519 IETF VRF test vectors."""

    def test_vectors(self, ed25519_ietf_vectors):
        """Test standard IETF vectors."""
        for vector in ed25519_ietf_vectors:
            self.verify_ietf_vector(vector, Ed25519)


# secp256r1 IETF vectors
@pytest.fixture(scope="module")
def secp256r1_ietf_vectors():
    return load_vectors("secp256r1_sha-256_tai_ietf.json")


class TestSecp256r1IETF(TestIETFVRF):
    """secp256r1 IETF VRF test vectors."""

    def test_vectors(self, secp256r1_ietf_vectors):
        """Test standard IETF vectors."""
        for vector in secp256r1_ietf_vectors:
            self.verify_ietf_vector(vector, Secp256r1)


# =============================================================================
# Pedersen VRF Tests
# =============================================================================


class TestPedersenVRF:
    """Test suite for Pedersen VRF test vectors."""

    @staticmethod
    def verify_pedersen_vector(vector: dict[str, Any], curve) -> None:
        """Verify a single Pedersen VRF test vector."""
        # Parse inputs
        sk = bytes.fromhex(vector["sk"])
        alpha = bytes.fromhex(vector["alpha"])
        salt = bytes.fromhex(vector["salt"]) if vector.get("salt") else b""
        ad = bytes.fromhex(vector["ad"]) if vector.get("ad") else b""
        expected_gamma = bytes.fromhex(vector["gamma"])
        expected_beta = bytes.fromhex(vector["beta"])
        expected_pk_com = bytes.fromhex(vector["proof_pk_com"])
        expected_r = bytes.fromhex(vector["proof_r"])
        expected_ok = bytes.fromhex(vector["proof_ok"])
        expected_s = bytes.fromhex(vector["proof_s"])
        expected_sb = bytes.fromhex(vector["proof_sb"])

        # Generate proof
        proof = PedersenVRF[curve].prove(alpha, sk, ad, salt)

        # Verify output point matches
        gamma_bytes = proof.output_point.point_to_string()
        assert gamma_bytes == expected_gamma, f"gamma mismatch: expected {expected_gamma.hex()}, got {gamma_bytes.hex()}"

        # Verify proof components
        assert proof.blinded_pk.point_to_string() == expected_pk_com, "pk_com mismatch"

        assert proof.result_point.point_to_string() == expected_r, "R mismatch"

        assert proof.ok.point_to_string() == expected_ok, "Ok mismatch"

        scalar_len = (curve.curve.PRIME_FIELD.bit_length() + 7) // 8
        s_bytes = Helpers.int_to_str(proof.s, curve.curve.ENDIAN, scalar_len)
        assert s_bytes == expected_s, f"s mismatch: expected {expected_s.hex()}, got {s_bytes.hex()}"

        sb_bytes = Helpers.int_to_str(proof.sb, curve.curve.ENDIAN, scalar_len)
        assert sb_bytes == expected_sb, f"sb mismatch: expected {expected_sb.hex()}, got {sb_bytes.hex()}"

        # Verify the proof
        assert proof.verify(alpha, ad), "Proof verification failed"

        # Verify output hash
        beta = PedersenVRF[curve].proof_to_hash(proof.output_point)
        assert beta == expected_beta, f"beta mismatch: expected {expected_beta.hex()}, got {beta.hex()}"


# Bandersnatch Pedersen vectors
@pytest.fixture(scope="module")
def bandersnatch_pedersen_vectors():
    return load_vectors("bandersnatch_sha-512_ell2_pedersen.json")


@pytest.fixture(scope="module")
def bandersnatch_pedersen_edge_vectors():
    return load_vectors("bandersnatch_sha-512_ell2_pedersen_edge_cases.json")


class TestBandersnatchPedersen(TestPedersenVRF):
    """Bandersnatch Pedersen VRF test vectors."""

    def test_vectors(self, bandersnatch_pedersen_vectors):
        """Test standard Pedersen vectors."""
        for vector in bandersnatch_pedersen_vectors:
            self.verify_pedersen_vector(vector, Bandersnatch)

    def test_edge_case_vectors(self, bandersnatch_pedersen_edge_vectors):
        """Test edge case Pedersen vectors."""
        for vector in bandersnatch_pedersen_edge_vectors:
            self.verify_pedersen_vector(vector, Bandersnatch)


# Ed25519 Pedersen vectors
@pytest.fixture(scope="module")
def ed25519_pedersen_vectors():
    return load_vectors("ed25519_sha-512_tai_pedersen.json")


class TestEd25519Pedersen(TestPedersenVRF):
    """Ed25519 Pedersen VRF test vectors."""

    def test_vectors(self, ed25519_pedersen_vectors):
        """Test standard Pedersen vectors."""
        for vector in ed25519_pedersen_vectors:
            self.verify_pedersen_vector(vector, Ed25519)


# secp256r1 Pedersen vectors
@pytest.fixture(scope="module")
def secp256r1_pedersen_vectors():
    return load_vectors("secp256r1_sha-256_tai_pedersen.json")


class TestSecp256r1Pedersen(TestPedersenVRF):
    """secp256r1 Pedersen VRF test vectors."""

    def test_vectors(self, secp256r1_pedersen_vectors):
        """Test standard Pedersen vectors."""
        for vector in secp256r1_pedersen_vectors:
            self.verify_pedersen_vector(vector, Secp256r1)


# =============================================================================
# Ring VRF Tests
# =============================================================================


class TestRingVRF:
    """Test suite for Ring VRF test vectors."""

    @staticmethod
    def verify_ring_vector(vector: dict[str, Any], curve) -> None:
        """Verify a single Ring VRF test vector."""
        # Parse inputs
        sk = bytes.fromhex(vector["sk"])
        pk = bytes.fromhex(vector["pk"])
        alpha = bytes.fromhex(vector["alpha"])
        ad = bytes.fromhex(vector["ad"]) if vector.get("ad") else b""
        expected_gamma = bytes.fromhex(vector["gamma"])
        expected_beta = bytes.fromhex(vector["beta"])
        ring_pks_bytes = bytes.fromhex(vector["ring_pks"])

        # Parse ring public keys
        point_len = curve.curve.POINT_LEN
        ring_pks = []
        for i in range(0, len(ring_pks_bytes), point_len):
            ring_pks.append(ring_pks_bytes[i : i + point_len])

        # Generate proof
        proof = RingVRF[curve].prove(alpha, ad, sk, pk, ring_pks)

        # Verify output point matches
        gamma_bytes = proof.pedersen_proof.output_point.point_to_string()
        assert gamma_bytes == expected_gamma, f"gamma mismatch: expected {expected_gamma.hex()}, got {gamma_bytes.hex()}"

        # Construct ring root and verify
        ring_root = RingVRF[curve].construct_ring_root(ring_pks)
        assert proof.verify(alpha, ad, ring_root), "Proof verification failed"

        # Verify output hash
        beta = RingVRF[curve].proof_to_hash(proof.pedersen_proof.output_point)
        assert beta == expected_beta, f"beta mismatch: expected {expected_beta.hex()}, got {beta.hex()}"


# Bandersnatch Ring vectors
@pytest.fixture(scope="module")
def bandersnatch_ring_vectors():
    return load_vectors("bandersnatch_sha-512_ell2_ring.json")


@pytest.fixture(scope="module")
def bandersnatch_ring_edge_vectors():
    return load_vectors("bandersnatch_sha-512_ell2_ring_edge_cases.json")


class TestBandersnatchRing(TestRingVRF):
    """Bandersnatch Ring VRF test vectors."""

    def test_vectors(self, bandersnatch_ring_vectors):
        """Test standard Ring vectors."""
        for vector in bandersnatch_ring_vectors:
            self.verify_ring_vector(vector, Bandersnatch)

    def test_edge_case_vectors(self, bandersnatch_ring_edge_vectors):
        """Test edge case Ring vectors."""
        for vector in bandersnatch_ring_edge_vectors:
            self.verify_ring_vector(vector, Bandersnatch)


# =============================================================================
# Negative Tests - Expected Failures
# =============================================================================


class TestNegativeCases:
    """Test cases that should fail verification."""

    def test_wrong_public_key_ietf(self):
        """IETF VRF verification should fail with wrong public key."""
        # Generate a valid proof
        sk1 = bytes.fromhex("0101010101010101010101010101010101010101010101010101010101010101")
        sk2 = bytes.fromhex("0202020202020202020202020202020202020202020202020202020202020202")

        pk1 = IETF_VRF[Bandersnatch].get_public_key(sk1)
        pk2 = IETF_VRF[Bandersnatch].get_public_key(sk2)

        alpha = b"test_input"
        ad = b"test_ad"

        # Generate proof with sk1
        proof = IETF_VRF[Bandersnatch].prove(alpha, sk1, ad)

        # Verify with correct key should pass
        assert proof.verify(pk1, alpha, ad)

        # Verify with wrong key should fail
        assert not proof.verify(pk2, alpha, ad)

    def test_wrong_input_ietf(self):
        """IETF VRF verification should fail with wrong input."""
        sk = bytes.fromhex("0101010101010101010101010101010101010101010101010101010101010101")
        pk = IETF_VRF[Bandersnatch].get_public_key(sk)

        alpha1 = b"correct_input"
        alpha2 = b"wrong_input"
        ad = b"test_ad"

        # Generate proof with alpha1
        proof = IETF_VRF[Bandersnatch].prove(alpha1, sk, ad)

        # Verify with correct input should pass
        assert proof.verify(pk, alpha1, ad)

        # Verify with wrong input should fail
        assert not proof.verify(pk, alpha2, ad)

    def test_wrong_ad_ietf(self):
        """IETF VRF verification should fail with wrong additional data."""
        sk = bytes.fromhex("0101010101010101010101010101010101010101010101010101010101010101")
        pk = IETF_VRF[Bandersnatch].get_public_key(sk)

        alpha = b"test_input"
        ad1 = b"correct_ad"
        ad2 = b"wrong_ad"

        # Generate proof with ad1
        proof = IETF_VRF[Bandersnatch].prove(alpha, sk, ad1)

        # Verify with correct ad should pass
        assert proof.verify(pk, alpha, ad1)

        # Verify with wrong ad should fail
        assert not proof.verify(pk, alpha, ad2)

    def test_wrong_input_pedersen(self):
        """Pedersen VRF verification should fail with wrong input."""
        sk = bytes.fromhex("0101010101010101010101010101010101010101010101010101010101010101")

        alpha1 = b"correct_input"
        alpha2 = b"wrong_input"
        ad = b"test_ad"

        # Generate proof with alpha1
        proof = PedersenVRF[Bandersnatch].prove(alpha1, sk, ad)

        # Verify with correct input should pass
        assert proof.verify(alpha1, ad)

        # Verify with wrong input should fail
        assert not proof.verify(alpha2, ad)

    def test_wrong_ring_root(self):
        """Ring VRF verification should fail with wrong ring root."""
        sk = bytes.fromhex("0101010101010101010101010101010101010101010101010101010101010101")
        pk = RingVRF[Bandersnatch].get_public_key(sk)

        # Create two different rings
        ring1 = [pk]
        for i in range(7):
            other_sk = (i + 2).to_bytes(32, "little")
            ring1.append(RingVRF[Bandersnatch].get_public_key(other_sk))

        ring2 = [pk]
        for i in range(7):
            other_sk = (i + 100).to_bytes(32, "little")
            ring2.append(RingVRF[Bandersnatch].get_public_key(other_sk))

        alpha = b"test_input"
        ad = b"test_ad"

        # Generate proof for ring1
        proof = RingVRF[Bandersnatch].prove(alpha, ad, sk, pk, ring1)

        # Verify with correct ring should pass
        ring_root1 = RingVRF[Bandersnatch].construct_ring_root(ring1)
        assert proof.verify(alpha, ad, ring_root1)

        # Verify with wrong ring should fail
        ring_root2 = RingVRF[Bandersnatch].construct_ring_root(ring2)
        assert not proof.verify(alpha, ad, ring_root2)


# =============================================================================
# Determinism Tests
# =============================================================================


class TestDeterminism:
    """Tests to verify proof generation is deterministic."""

    def test_ietf_deterministic(self):
        """IETF VRF proofs should be deterministic."""
        sk = bytes.fromhex("0101010101010101010101010101010101010101010101010101010101010101")
        alpha = b"deterministic_test"
        ad = b"test_ad"

        proof1 = IETF_VRF[Bandersnatch].prove(alpha, sk, ad)
        proof2 = IETF_VRF[Bandersnatch].prove(alpha, sk, ad)

        assert proof1.output_point.point_to_string() == proof2.output_point.point_to_string()
        assert proof1.c == proof2.c
        assert proof1.s == proof2.s

    def test_pedersen_deterministic(self):
        """Pedersen VRF proofs should be deterministic."""
        sk = bytes.fromhex("0101010101010101010101010101010101010101010101010101010101010101")
        alpha = b"deterministic_test"
        ad = b"test_ad"

        proof1 = PedersenVRF[Bandersnatch].prove(alpha, sk, ad)
        proof2 = PedersenVRF[Bandersnatch].prove(alpha, sk, ad)

        assert proof1.output_point.point_to_string() == proof2.output_point.point_to_string()
        assert proof1.blinded_pk.point_to_string() == proof2.blinded_pk.point_to_string()
        assert proof1.result_point.point_to_string() == proof2.result_point.point_to_string()
        assert proof1.ok.point_to_string() == proof2.ok.point_to_string()
        assert proof1.s == proof2.s
        assert proof1.sb == proof2.sb
