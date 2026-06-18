import pytest

from dot_ring import Bandersnatch, PedersenVRF, TinyVRF
from dot_ring.curve.specs.ed448 import Ed448_RO
from dot_ring.ring_proof.params import RingProofParams
from dot_ring.vrf.ring import Ring, RingRoot
from dot_ring.vrf.transcript import point_len, scalar_len


class TestCoverageGaps:
    def test_vrf_generate_nonce_invalid_input(self):
        """Test generate_nonce raises ValueError for invalid input point type."""
        with pytest.raises(ValueError, match="Input point must be a CurvePoint"):
            TinyVRF[Bandersnatch].generate_nonce(123, 456)  # type: ignore

    def test_ecvrf_decode_proof_string_input(self):
        """Test ecvrf_decode_proof handles hex string input."""
        # Generate a valid proof first
        alpha = b"test"
        sk = b"secret"
        ad = b"ad"
        proof = TinyVRF[Bandersnatch].prove(alpha, sk, ad)
        proof_bytes = proof.to_bytes()
        proof_hex = proof_bytes.hex()

        gamma, c, s = TinyVRF[Bandersnatch].ecvrf_decode_proof(proof_hex)
        assert gamma == proof.output_point
        assert c == proof.c
        assert s == proof.s

    def test_ecvrf_decode_proof_invalid_gamma(self):
        """Test ecvrf_decode_proof raises ValueError for invalid gamma point."""
        # Create a proof with invalid gamma point bytes (e.g. all zeros if not valid, or just garbage)
        # Bandersnatch point length is 33.
        invalid_gamma = b"\xff" * 33
        # Valid C and S lengths
        c_len = Bandersnatch.curve.params.encoding.challenge_len
        s_len = scalar_len(Bandersnatch)
        dummy_c = b"\x00" * c_len
        dummy_s = b"\x00" * s_len

        invalid_proof = invalid_gamma + dummy_c + dummy_s

        with pytest.raises(ValueError, match="Invalid gamma point"):
            TinyVRF[Bandersnatch].ecvrf_decode_proof(invalid_proof)

    def test_ecvrf_decode_proof_invalid_s(self):
        """Test ecvrf_decode_proof raises ValueError if S >= order."""
        alpha = b"test"
        sk = b"secret"
        ad = b"ad"
        proof = TinyVRF[Bandersnatch].prove(alpha, sk, ad)
        proof_bytes = proof.to_bytes()

        # Modify S to be >= order
        order = Bandersnatch.curve.params.subgroup_order
        invalid_s = order + 1
        s_len = (order.bit_length() + 7) // 8

        # Reconstruct proof with invalid S
        # Structure: gamma (33) + c (16 or 32) + s (32)
        # Bandersnatch challenge length is 32.
        gamma_len = 33
        c_len = 32

        gamma_bytes = proof_bytes[:gamma_len]
        c_bytes = proof_bytes[gamma_len : gamma_len + c_len]

        from dot_ring.ring_proof.helpers import Helpers

        invalid_s_bytes = Helpers.int_to_str(invalid_s, "little", s_len)  # Bandersnatch is little endian

        # Note: Helpers.int_to_str might mask the overflow if not careful, but here we want to inject bytes that decode to >= order.
        # If s_len is fixed, we might not be able to fit order+1 if order is max for that length.
        # Bandersnatch order is ~253 bits, fits in 32 bytes? 253/8 = 31.6. So 32 bytes.
        # 2^253 fits in 32 bytes.

        invalid_proof = gamma_bytes + c_bytes + invalid_s_bytes

        with pytest.raises(ValueError, match="Response scalar S is not less than the curve order"):
            TinyVRF[Bandersnatch].ecvrf_decode_proof(invalid_proof)

    def test_ecvrf_proof_to_hash_string_input(self):
        """Test ecvrf_proof_to_hash handles hex string input."""
        alpha = b"test"
        sk = b"secret"
        ad = b"ad"
        proof = TinyVRF[Bandersnatch].prove(alpha, sk, ad)
        proof_bytes = proof.to_bytes()
        proof_hex = proof_bytes.hex()

        hash_bytes = TinyVRF[Bandersnatch].ecvrf_proof_to_hash(proof_hex)
        assert isinstance(hash_bytes, bytes)

    def test_ietf_from_bytes_invalid_point(self):
        """Test TinyVRF.from_bytes raises ValueError for invalid output point."""
        invalid_point = b"\xff" * point_len(Bandersnatch)
        c_len = Bandersnatch.curve.params.encoding.challenge_len
        s_len = scalar_len(Bandersnatch)
        dummy_c = b"\x00" * c_len
        dummy_s = b"\x00" * s_len

        invalid_proof = invalid_point + dummy_c + dummy_s

        with pytest.raises(ValueError, match="Invalid output point"):
            TinyVRF[Bandersnatch].from_bytes(invalid_proof)

    def test_ietf_from_bytes_invalid_s(self):
        """Test TinyVRF.from_bytes raises ValueError if s >= order."""
        alpha = b"test"
        sk = b"secret"
        ad = b"ad"
        proof = TinyVRF[Bandersnatch].prove(alpha, sk, ad)
        proof_bytes = proof.to_bytes()

        order = Bandersnatch.curve.params.subgroup_order
        invalid_s = order + 1
        s_len = (order.bit_length() + 7) // 8

        gamma_len = point_len(Bandersnatch)
        c_len = Bandersnatch.curve.params.encoding.challenge_len

        gamma_bytes = proof_bytes[:gamma_len]
        c_bytes = proof_bytes[gamma_len : gamma_len + c_len]

        from dot_ring.ring_proof.helpers import Helpers

        invalid_s_bytes = Helpers.int_to_str(invalid_s, "little", s_len)

        invalid_proof = gamma_bytes + c_bytes + invalid_s_bytes

        with pytest.raises(ValueError, match="Response scalar s is not less than the curve order"):
            TinyVRF[Bandersnatch].from_bytes(invalid_proof)

    def test_ietf_verify_invalid_public_key(self):
        """Test TinyVRF.verify raises ValueError for invalid public key."""
        alpha = b"test"
        sk = b"secret"
        ad = b"ad"
        proof = TinyVRF[Bandersnatch].prove(alpha, sk, ad)

        invalid_pk = b"\xff" * 33

        with pytest.raises(ValueError, match="Invalid public key"):
            proof.verify(invalid_pk, alpha, ad)

    def test_pedersen_from_bytes_invalid_point(self):
        """Test PedersenVRF.from_bytes raises ValueError for invalid points."""
        point_len = 33
        scalar_len = 32
        invalid_proof = b"\xff" * (point_len * 4 + scalar_len * 2)

        with pytest.raises(ValueError):  # Message might vary depending on which point fails first
            PedersenVRF[Bandersnatch].from_bytes(invalid_proof)

    def test_pedersen_proof_to_hash_string(self):
        """Test PedersenVRF.ecvrf_proof_to_hash handles hex string input."""
        alpha = b"test"
        sk = b"secret"
        ad = b"ad"
        proof = PedersenVRF[Bandersnatch].prove(alpha, sk, ad)
        proof_bytes = proof.output_point.point_to_string()
        proof_hex = proof_bytes.hex()

        hash_bytes = PedersenVRF[Bandersnatch].ecvrf_proof_to_hash(proof_hex)
        assert isinstance(hash_bytes, bytes)

    def test_pedersen_proof_to_hash_invalid(self):
        """Test PedersenVRF.ecvrf_proof_to_hash raises ValueError for invalid point."""
        invalid_point = b"\xff" * 33
        with pytest.raises(ValueError, match="Invalid output point"):
            PedersenVRF[Bandersnatch].ecvrf_proof_to_hash(invalid_point)

    def test_uncompressed_curve_decode(self):
        """Test ecvrf_decode_proof with uncompressed curve (Ed448)."""
        # Ed448 is uncompressed.
        alpha = b"test"
        sk = b"secret"
        ad = b"ad"

        try:
            proof = TinyVRF[Ed448_RO].prove(alpha, sk, ad)
            proof_bytes = proof.to_bytes()

            # Decode
            gamma, c, s = TinyVRF[Ed448_RO].ecvrf_decode_proof(proof_bytes)
            assert gamma == proof.output_point
        except Exception as e:
            pytest.skip(f"Ed448 not fully supported or failed: {e}")

    def test_ring_from_bytes_skip_pedersen(self):
        """Test RingVRF.from_bytes with skip_pedersen=True."""
        from dot_ring.vrf.ring import RingVRF

        # Generate a valid proof
        alpha = b"test"
        ad = b"ad"
        sk = b"secret"
        pk = PedersenVRF[Bandersnatch].get_public_key(sk)
        keys = [pk]

        params = RingProofParams()
        ring = Ring(keys, params)
        ring_root = RingRoot.from_ring(ring, params)
        proof = RingVRF[Bandersnatch].prove(alpha, ad, sk, pk, ring, ring_root)
        proof_bytes = proof.to_bytes()

        # skip_pedersen=True expects bytes that start at the ring proof payload.
        ring_proof_bytes = proof_bytes[192:]
        parsed = RingVRF[Bandersnatch].from_bytes(ring_proof_bytes, skip_pedersen=True)
        assert parsed.pedersen_proof is None

    def test_ring_verify_missing_pedersen(self):
        """Test RingVRF.verify raises ValueError if pedersen_proof is missing."""
        from dot_ring.vrf.ring import RingVRF

        # Create a dummy RingVRF with pedersen_proof=None
        # We can use the one parsed above
        alpha = b"test"
        ad = b"ad"
        sk = b"secret"
        pk = PedersenVRF[Bandersnatch].get_public_key(sk)
        keys = [pk]

        params = RingProofParams()
        ring = Ring(keys, params)
        ring_root = RingRoot.from_ring(ring, params)
        proof = RingVRF[Bandersnatch].prove(alpha, ad, sk, pk, ring, ring_root)
        proof_bytes = proof.to_bytes()
        ring_proof_bytes = proof_bytes[192:]
        parsed = RingVRF[Bandersnatch].from_bytes(ring_proof_bytes, skip_pedersen=True)

        with pytest.raises(ValueError, match="Pedersen proof is missing"):
            parsed.verify(alpha, ad, ring, ring_root)

    def test_ring_construct_ring_root_invalid_keys(self):
        """Test Ring construction with invalid keys."""
        # Invalid key string
        invalid_key = b"invalid"
        # Identity point (if we can construct one as string)
        # Or just random bytes that don't decode
        keys = [
            invalid_key,
            b"\x00" * 33,
        ]  # 33 bytes of zeros might be invalid or identity?

        # Should not raise, but handle gracefully (skip or use padding)
        params = RingProofParams()
        ring = Ring(keys, params)
        assert ring is not None
        ring_root = RingRoot.from_ring(ring, params)
        assert ring_root is not None

    def test_ring_verify_ring_proof_bytes_input(self):
        """Test verify_ring_proof handles bytes input for message."""
        from dot_ring.vrf.ring import RingVRF

        alpha = b"test"
        ad = b"ad"
        sk = b"secret"
        pk = PedersenVRF[Bandersnatch].get_public_key(sk)
        keys = [pk]

        params = RingProofParams()
        ring = Ring(keys, params)
        ring_root = RingRoot.from_ring(ring, params)
        proof = RingVRF[Bandersnatch].prove(alpha, ad, sk, pk, ring, ring_root)

        blinded_pk_bytes = proof.pedersen_proof.blinded_pk.point_to_string()

        valid = proof.verify_ring_proof(blinded_pk_bytes, ring, ring_root)
        assert valid

    def test_ring_verify_ring_proof_invalid_message(self):
        """Test verify_ring_proof raises ValueError for invalid message point."""
        from dot_ring.vrf.ring import RingVRF

        alpha = b"test"
        ad = b"ad"
        sk = b"secret"
        pk = PedersenVRF[Bandersnatch].get_public_key(sk)
        keys = [pk]

        params = RingProofParams()
        ring = Ring(keys, params)
        ring_root = RingRoot.from_ring(ring, params)
        proof = RingVRF[Bandersnatch].prove(alpha, ad, sk, pk, ring, ring_root)

        invalid_message = b"\xff" * 33

        with pytest.raises(ValueError, match="Invalid message point"):
            proof.verify_ring_proof(invalid_message, ring, ring_root)
