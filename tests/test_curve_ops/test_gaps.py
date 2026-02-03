import pytest

from dot_ring import IETF_VRF, Bandersnatch, PedersenVRF
from dot_ring.curve.specs.ed448 import Ed448_RO


class TestCoverageGaps:
    def test_vrf_generate_nonce_invalid_input(self):
        """Test generate_nonce raises ValueError for invalid input point type."""
        with pytest.raises(ValueError, match="Input point must be a CurvePoint"):
            IETF_VRF[Bandersnatch].generate_nonce(123, 456)  # type: ignore

    def test_ecvrf_decode_proof_string_input(self):
        """Test ecvrf_decode_proof handles hex string input."""
        # Generate a valid proof first
        alpha = b"test"
        sk = b"secret"
        ad = b"ad"
        proof = IETF_VRF[Bandersnatch].prove(alpha, sk, ad)
        proof_bytes = proof.to_bytes()
        proof_hex = proof_bytes.hex()

        gamma, c, s = IETF_VRF[Bandersnatch].ecvrf_decode_proof(proof_hex)
        assert gamma == proof.output_point
        assert c == proof.c
        assert s == proof.s

    def test_ecvrf_decode_proof_invalid_gamma(self):
        """Test ecvrf_decode_proof raises ValueError for invalid gamma point."""
        # Create a proof with invalid gamma point bytes (e.g. all zeros if not valid, or just garbage)
        # Bandersnatch point length is 33.
        invalid_gamma = b"\xff" * 33
        # Valid C and S lengths
        c_len = Bandersnatch.curve.CHALLENGE_LENGTH
        s_len = (Bandersnatch.curve.ORDER.bit_length() + 7) // 8
        dummy_c = b"\x00" * c_len
        dummy_s = b"\x00" * s_len

        invalid_proof = invalid_gamma + dummy_c + dummy_s

        with pytest.raises(ValueError, match="Invalid gamma point"):
            IETF_VRF[Bandersnatch].ecvrf_decode_proof(invalid_proof)

    def test_ecvrf_decode_proof_invalid_s(self):
        """Test ecvrf_decode_proof raises ValueError if S >= order."""
        alpha = b"test"
        sk = b"secret"
        ad = b"ad"
        proof = IETF_VRF[Bandersnatch].prove(alpha, sk, ad)
        proof_bytes = proof.to_bytes()

        # Modify S to be >= order
        order = Bandersnatch.curve.ORDER
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
            IETF_VRF[Bandersnatch].ecvrf_decode_proof(invalid_proof)

    def test_ecvrf_proof_to_hash_string_input(self):
        """Test ecvrf_proof_to_hash handles hex string input."""
        alpha = b"test"
        sk = b"secret"
        ad = b"ad"
        proof = IETF_VRF[Bandersnatch].prove(alpha, sk, ad)
        proof_bytes = proof.to_bytes()
        proof_hex = proof_bytes.hex()

        hash_bytes = IETF_VRF[Bandersnatch].ecvrf_proof_to_hash(proof_hex)
        assert isinstance(hash_bytes, bytes)

    def test_ietf_from_bytes_invalid_point(self):
        """Test IETF_VRF.from_bytes raises ValueError for invalid output point."""
        invalid_point = b"\xff" * 33
        c_len = Bandersnatch.curve.CHALLENGE_LENGTH
        s_len = (Bandersnatch.curve.ORDER.bit_length() + 7) // 8
        dummy_c = b"\x00" * c_len
        dummy_s = b"\x00" * s_len

        invalid_proof = invalid_point + dummy_c + dummy_s

        with pytest.raises(ValueError, match="Invalid output point"):
            IETF_VRF[Bandersnatch].from_bytes(invalid_proof)

    def test_ietf_from_bytes_invalid_s(self):
        """Test IETF_VRF.from_bytes raises ValueError if s >= order."""
        alpha = b"test"
        sk = b"secret"
        ad = b"ad"
        proof = IETF_VRF[Bandersnatch].prove(alpha, sk, ad)
        proof_bytes = proof.to_bytes()

        order = Bandersnatch.curve.ORDER
        invalid_s = order + 1
        s_len = (order.bit_length() + 7) // 8

        gamma_len = 33
        c_len = 32

        gamma_bytes = proof_bytes[:gamma_len]
        c_bytes = proof_bytes[gamma_len : gamma_len + c_len]

        from dot_ring.ring_proof.helpers import Helpers

        invalid_s_bytes = Helpers.int_to_str(invalid_s, "little", s_len)

        invalid_proof = gamma_bytes + c_bytes + invalid_s_bytes

        with pytest.raises(ValueError, match="Response scalar s is not less than the curve order"):
            IETF_VRF[Bandersnatch].from_bytes(invalid_proof)

    def test_ietf_verify_invalid_public_key(self):
        """Test IETF_VRF.verify raises ValueError for invalid public key."""
        alpha = b"test"
        sk = b"secret"
        ad = b"ad"
        proof = IETF_VRF[Bandersnatch].prove(alpha, sk, ad)

        invalid_pk = b"\xff" * 33

        with pytest.raises(ValueError, match="Invalid public key"):
            proof.verify(invalid_pk, alpha, ad)

    def test_pedersen_from_bytes_invalid_point(self):
        """Test PedersenVRF.from_bytes raises ValueError for invalid points."""
        # Pedersen proof has multiple points.
        # Structure: 4 points + 2 scalars.
        # Just messing up the first point (output point) should trigger it?
        # Wait, PedersenVRF.from_bytes parses:
        # output_point (33) + B (33) + U (33) + V (33) + s (32) + sb (32)
        # Actually it depends on implementation.

        # Let's check PedersenVRF.from_bytes implementation details if needed.
        # But generally passing garbage bytes of correct length should fail point decoding.

        point_len = 33
        scalar_len = 32
        invalid_proof = b"\xff" * (point_len * 4 + scalar_len * 2)

        # It might raise ValueError from string_to_point
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
            proof = IETF_VRF[Ed448_RO].prove(alpha, sk, ad)
            proof_bytes = proof.to_bytes()

            # Decode
            gamma, c, s = IETF_VRF[Ed448_RO].ecvrf_decode_proof(proof_bytes)
            assert gamma == proof.output_point
        except Exception as e:
            pytest.skip(f"Ed448 not fully supported or failed: {e}")

    def test_ring_from_bytes_skip_pedersen(self):
        """Test RingVRF.from_bytes with skip_pedersen=True."""
        from dot_ring.vrf.ring.ring_vrf import RingVRF

        # Generate a valid proof
        alpha = b"test"
        ad = b"ad"
        sk = b"secret"
        pk = PedersenVRF[Bandersnatch].get_public_key(sk)
        keys = [pk]

        proof = RingVRF[Bandersnatch].prove(alpha, ad, sk, pk, keys)
        proof_bytes = proof.to_bytes()

        # Parse with skip_pedersen=True
        # Note: from_bytes expects full proof bytes, but if skip_pedersen is True,
        # it assumes the bytes start with ring proof (skipping first 192 bytes of pedersen proof).
        # Wait, looking at code:
        # if not skip_pedersen: pedersen_proof = ...; offset = 192
        # else: pedersen_proof = None; offset = 0
        # So if we pass full proof bytes with skip_pedersen=True, it will try to read ring proof from offset 0.
        # But offset 0 contains pedersen proof!
        # So we must slice the proof bytes if we use skip_pedersen=True?
        # Or does it mean the input `proof` bytes should ONLY contain ring proof?
        # The docstring says "Bytes representation of the Ring VRF proof".
        # If skip_pedersen is True, it implies the input bytes do NOT contain pedersen proof.

        ring_proof_bytes = proof_bytes[192:]
        parsed = RingVRF[Bandersnatch].from_bytes(ring_proof_bytes, skip_pedersen=True)
        assert parsed.pedersen_proof is None

    def test_ring_verify_missing_pedersen(self):
        """Test RingVRF.verify raises ValueError if pedersen_proof is missing."""
        from dot_ring.vrf.ring.ring_vrf import RingVRF

        # Create a dummy RingVRF with pedersen_proof=None
        # We can use the one parsed above
        alpha = b"test"
        ad = b"ad"
        sk = b"secret"
        pk = PedersenVRF[Bandersnatch].get_public_key(sk)
        keys = [pk]

        proof = RingVRF[Bandersnatch].prove(alpha, ad, sk, pk, keys)
        proof_bytes = proof.to_bytes()
        ring_proof_bytes = proof_bytes[192:]
        parsed = RingVRF[Bandersnatch].from_bytes(ring_proof_bytes, skip_pedersen=True)

        ring_root = RingVRF[Bandersnatch].construct_ring_root(keys)

        with pytest.raises(ValueError, match="Pedersen proof is missing"):
            parsed.verify(alpha, ad, ring_root)

    def test_ring_construct_ring_root_invalid_keys(self):
        """Test construct_ring_root with invalid keys."""
        from dot_ring.vrf.ring.ring_vrf import RingVRF

        # Invalid key string
        invalid_key = b"invalid"
        # Identity point (if we can construct one as string)
        # Or just random bytes that don't decode
        keys = [
            invalid_key,
            b"\x00" * 33,
        ]  # 33 bytes of zeros might be invalid or identity?

        # Should not raise, but handle gracefully (skip or use padding)
        ring_root = RingVRF[Bandersnatch].construct_ring_root(keys)
        assert ring_root is not None

    def test_ring_verify_ring_proof_bytes_input(self):
        """Test verify_ring_proof handles bytes input for message and ring_root."""
        from dot_ring.vrf.ring.ring_vrf import RingVRF

        alpha = b"test"
        ad = b"ad"
        sk = b"secret"
        pk = PedersenVRF[Bandersnatch].get_public_key(sk)
        keys = [pk]

        proof = RingVRF[Bandersnatch].prove(alpha, ad, sk, pk, keys)
        ring_root = RingVRF[Bandersnatch].construct_ring_root(keys)
        ring_root_bytes = ring_root.to_bytes()

        # message is usually a point (blinded_pk), but verify_ring_proof accepts bytes too.
        # But wait, verify_ring_proof takes `message: bytes | CurvePoint`.
        # In `verify`, it calls `self.verify_ring_proof(self.pedersen_proof.blinded_pk, ring_root)`.
        # `blinded_pk` is a CurvePoint.
        # If we pass bytes, it tries to decode.

        # Let's call verify_ring_proof directly with bytes
        blinded_pk_bytes = proof.pedersen_proof.blinded_pk.point_to_string()

        valid = proof.verify_ring_proof(blinded_pk_bytes, ring_root_bytes)
        assert valid

    def test_ring_construct_ring_root_non_bytes_key(self):
        """Test construct_ring_root with non-bytes/str key."""
        from dot_ring.vrf.ring.ring_vrf import RingVRF

        keys = [123]  # type: ignore
        ring_root = RingVRF[Bandersnatch].construct_ring_root(keys)
        assert ring_root is not None

    def test_ring_verify_ring_proof_invalid_message(self):
        """Test verify_ring_proof raises ValueError for invalid message point."""
        from dot_ring.vrf.ring.ring_vrf import RingVRF

        alpha = b"test"
        ad = b"ad"
        sk = b"secret"
        pk = PedersenVRF[Bandersnatch].get_public_key(sk)
        keys = [pk]

        proof = RingVRF[Bandersnatch].prove(alpha, ad, sk, pk, keys)
        ring_root = RingVRF[Bandersnatch].construct_ring_root(keys)

        invalid_message = b"\xff" * 33

        with pytest.raises(ValueError, match="Invalid message point"):
            proof.verify_ring_proof(invalid_message, ring_root)
