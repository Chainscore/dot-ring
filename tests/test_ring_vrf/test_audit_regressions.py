import pytest

from dot_ring import Bandersnatch, RingVRF
from dot_ring.ring_proof.constants import PaddingPoint
from dot_ring.ring_proof.params import RingProofParams
from dot_ring.vrf.pedersen import PedersenVRF
from dot_ring.vrf.ring import Ring, RingContext, RingRoot
from dot_ring.vrf.transcript import point_len


def _keys(count: int) -> list[bytes]:
    return [RingVRF[Bandersnatch].get_public_key((i + 1).to_bytes(32, "little")) for i in range(count)]


def _point_tuple(key: bytes) -> tuple[int, int]:
    point = Bandersnatch.string_to_point(key)
    assert not isinstance(point, str)
    return (point.x, point.y)


def _proof_fixture():
    sk = bytes.fromhex("01" * 32)
    pk = RingVRF[Bandersnatch].get_public_key(sk)
    params = RingProofParams(test_vectors=True)
    ring = Ring([pk, *_keys(7)[1:]], params)
    ring_root = RingRoot.from_ring(ring, params)
    proof = RingVRF[Bandersnatch].prove(b"audit-input", b"audit-ad", sk, pk, ring, ring_root)
    return sk, pk, ring, ring_root, proof


def test_ring_verification_rejects_mismatched_ring_for_same_root():
    sk, pk, ring, ring_root, proof = _proof_fixture()
    other_ring = Ring([pk, *_keys(7)], ring.params)

    assert proof.verify(b"audit-input", b"audit-ad", ring, ring_root)
    assert not proof.verify(b"audit-input", b"audit-ad", other_ring, ring_root)


def test_ring_root_match_rejects_mismatched_ring():
    _, pk, ring, ring_root, _ = _proof_fixture()
    other_ring = Ring([pk, *_keys(7)], ring.params)

    assert ring_root.matches_ring(ring)
    assert ring_root.matches_ring(ring)
    assert not ring_root.matches_ring(other_ring)
    assert not ring_root.matches_ring(other_ring)


def test_ring_keys_pad_decode_failures_in_place():
    pk1, pk2 = _keys(2)
    identity = (1).to_bytes(32, "little")
    ring = Ring([pk1, b"", identity, pk2], RingProofParams(test_vectors=True))

    assert ring.nm_points[0] == _point_tuple(pk1)
    assert ring.nm_points[1] == PaddingPoint
    assert ring.nm_points[2] == PaddingPoint
    assert ring.nm_points[3] == _point_tuple(pk2)


def test_ring_vrf_from_bytes_rejects_trailing_bytes():
    _, _, _, ring_root, proof = _proof_fixture()

    with pytest.raises(ValueError, match="Ring VRF proof must be exactly"):
        RingVRF[Bandersnatch].from_bytes(proof.to_bytes() + b"junk")
    with pytest.raises(ValueError, match="ring root must be exactly"):
        RingRoot.from_bytes(ring_root.to_bytes() + b"junk")


def test_ring_root_from_bytes_cache_returns_fresh_root():
    _, _, _, ring_root, _ = _proof_fixture()
    root_bytes = ring_root.to_bytes()

    parsed1 = RingRoot.from_bytes(root_bytes, ring_root.params)
    parsed2 = RingRoot.from_bytes(root_bytes, ring_root.params)

    assert parsed1.to_bytes() == root_bytes
    assert parsed2.to_bytes() == root_bytes
    assert parsed1 is not parsed2
    assert parsed1.px.commitment is not parsed2.px.commitment


def test_pedersen_from_bytes_rejects_noncanonical_scalars():
    _, _, _, _, proof = _proof_fixture()
    pedersen_bytes = bytearray(proof.pedersen_proof.to_bytes())
    scalar_offset = 4 * point_len(Bandersnatch)
    s = int.from_bytes(pedersen_bytes[scalar_offset : scalar_offset + 32], "little")
    pedersen_bytes[scalar_offset : scalar_offset + 32] = (s + Bandersnatch.curve.params.subgroup_order).to_bytes(32, "little")

    with pytest.raises(ValueError, match="not canonical"):
        PedersenVRF[Bandersnatch].from_bytes(bytes(pedersen_bytes))
    with pytest.raises(ValueError, match="not canonical"):
        RingVRF[Bandersnatch].from_bytes(bytes(pedersen_bytes) + proof.to_bytes()[len(pedersen_bytes) :])


def test_prove_rejects_producer_key_that_does_not_match_secret():
    sk1 = bytes.fromhex("01" * 32)
    pk1 = RingVRF[Bandersnatch].get_public_key(sk1)
    pk2 = RingVRF[Bandersnatch].get_public_key(bytes.fromhex("02" * 32))
    params = RingProofParams(test_vectors=True)
    ring = Ring([pk1, pk2], params)
    ring_root = RingRoot.from_ring(ring, params)

    with pytest.raises(ValueError, match="producer_key does not match secret_key"):
        RingVRF[Bandersnatch].prove(b"audit-input", b"audit-ad", sk1, pk2, ring, ring_root)


def test_verifier_key_builder_caches_root_when_full():
    keys = _keys(8)
    params = RingProofParams(test_vectors=True, max_ring_size=8)
    context = RingContext(params)
    builder = context.verifier_key_builder()

    builder.append(keys)
    built_root = builder.finalize()
    direct_root = context.verifier_key(keys)

    assert built_root.to_bytes() == direct_root.to_bytes()
    assert builder.finalize() is built_root
    with pytest.raises(ValueError, match="too many keys"):
        builder.push(keys[0])


def test_unsupported_params_fail_at_construction():
    with pytest.raises(ValueError, match="padding_rows must be 4"):
        RingProofParams(padding_rows=5, max_ring_size=1)
    params = RingProofParams.from_ring_size(2047)
    assert params.domain_size == 4096
    assert params.max_ring_size == 3839
