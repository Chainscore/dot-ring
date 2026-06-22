import copy
import json
from pathlib import Path

import pytest

from dot_ring.curve.specs.baby_jubjub import BabyJubJub
from dot_ring.curve.specs.bandersnatch import Bandersnatch, Bandersnatch_SHAKE128
from dot_ring.curve.specs.bandersnatch_sw import Bandersnatch_SW
from dot_ring.curve.specs.ed25519 import Ed25519_TAI
from dot_ring.curve.specs.jubjub import JubJub
from dot_ring.curve.specs.p256 import P256_TAI
from dot_ring.ring_proof.params import RingProofParams
from dot_ring.vrf.ietf import ThinVRF, TinyVRF
from dot_ring.vrf.pedersen import PedersenVRF
from dot_ring.vrf.ring import Ring, RingRoot, RingVRF
from scripts.generate_test_vectors import SUITES as GENERATED_SUITES
from scripts.generate_test_vectors import scheme_vectors
from tests.vector_helpers import bytes_from_fields, load_json_vectors, pedersen_proof_bytes, ring_proof_bytes, thin_proof_bytes, tiny_proof_bytes

VECTORS = Path(__file__).parent / "vectors" / "ark-vrf"

SUITES = [
    (Bandersnatch, "bandersnatch_sha-512_ell2", 32),
    (Bandersnatch_SW, "bandersnatch_sw_sha-512_tai", 33),
    (Bandersnatch_SHAKE128, "bandersnatch_shake128_ell2", 32),
    (Ed25519_TAI, "ed25519_sha-512_tai", 32),
    (P256_TAI, "secp256r1_sha-256_tai", 33),
    (JubJub, "jubjub_sha-512_tai", 32),
    (BabyJubJub, "baby-jubjub_sha-512_tai", 32),
]


def load(name: str) -> list[dict[str, str]]:
    return load_json_vectors(VECTORS, name)


def test_generated_vectors_match_ark_vrf_tiny_thin_pedersen() -> None:
    for suite in GENERATED_SUITES:
        for scheme in ("tiny", "thin", "pedersen"):
            assert json.dumps(scheme_vectors(suite, scheme), indent=2) == (VECTORS / f"{suite.prefix}_{scheme}.json").read_text()


@pytest.mark.parametrize("curve,prefix,point_len", SUITES)
def test_tiny_vectors(curve, prefix: str, point_len: int) -> None:
    for vector in load(f"{prefix}_tiny.json"):
        sk = bytes.fromhex(vector["sk"])
        alpha = bytes.fromhex(vector["alpha"])
        ad = bytes.fromhex(vector["ad"])
        proof = TinyVRF[curve].prove(alpha, sk, ad)
        proof_bytes = proof.encode()

        assert curve.public_key_from_secret(sk).hex() == vector["pk"]
        assert curve.point_type.encode_to_curve(alpha).point_to_string().hex() == vector["h"]
        assert proof_bytes == tiny_proof_bytes(vector)
        assert TinyVRF[curve].proof_to_hash(proof.output_point).hex() == vector["beta"]
        assert proof.verify(bytes.fromhex(vector["pk"]), alpha, ad)
        assert TinyVRF[curve].decode(proof_bytes).encode() == proof_bytes
        assert len(proof.output_point.point_to_string()) == point_len


@pytest.mark.parametrize("curve,prefix,_point_len", SUITES)
def test_thin_vectors(curve, prefix: str, _point_len: int) -> None:
    for vector in load(f"{prefix}_thin.json"):
        sk = bytes.fromhex(vector["sk"])
        alpha = bytes.fromhex(vector["alpha"])
        ad = bytes.fromhex(vector["ad"])
        proof = ThinVRF[curve].prove(alpha, sk, ad)
        proof_bytes = proof.encode()

        assert proof_bytes == thin_proof_bytes(vector)
        assert proof.verify(bytes.fromhex(vector["pk"]), alpha, ad)
        assert ThinVRF[curve].decode(proof_bytes).encode() == proof_bytes


@pytest.mark.parametrize("curve,prefix,_point_len", SUITES)
def test_pedersen_vectors(curve, prefix: str, _point_len: int) -> None:
    for vector in load(f"{prefix}_pedersen.json"):
        sk = bytes.fromhex(vector["sk"])
        alpha = bytes.fromhex(vector["alpha"])
        ad = bytes.fromhex(vector["ad"])
        proof = PedersenVRF[curve].prove(alpha, sk, ad)
        proof_bytes = proof.encode()

        assert proof_bytes == pedersen_proof_bytes(vector)
        assert proof.verify(alpha, ad)
        assert PedersenVRF[curve].decode(proof_bytes).encode() == proof_bytes


@pytest.mark.parametrize("curve,prefix,point_len", SUITES)
def test_rejects_invalid_point_encodings(curve, prefix: str, point_len: int) -> None:
    invalid_point = b"\xff" * point_len

    tiny_vector = load(f"{prefix}_tiny.json")[0]
    tiny_bytes = invalid_point + bytes_from_fields(tiny_vector, "proof_c", "proof_s")
    with pytest.raises(ValueError, match="INVALID|Invalid"):
        TinyVRF[curve].decode(tiny_bytes)

    thin_vector = load(f"{prefix}_thin.json")[0]
    thin_bytes = invalid_point + bytes_from_fields(thin_vector, "proof_r", "proof_s")
    with pytest.raises(ValueError, match="INVALID|Invalid"):
        ThinVRF[curve].decode(thin_bytes)

    pedersen_vector = load(f"{prefix}_pedersen.json")[0]
    pedersen_bytes = invalid_point + bytes_from_fields(pedersen_vector, "proof_pk_com", "proof_r", "proof_ok", "proof_s", "proof_sb")
    with pytest.raises(ValueError, match="INVALID|Invalid"):
        PedersenVRF[curve].decode(pedersen_bytes)


@pytest.mark.parametrize(
    "curve,filename",
    [
        (Bandersnatch, "bandersnatch_sha-512_ell2_ring.json"),
        (Bandersnatch_SHAKE128, "bandersnatch_shake128_ell2_ring.json"),
        (JubJub, "jubjub_sha-512_tai_ring.json"),
    ],
)
def test_ring_vectors(curve, filename: str) -> None:
    for vector in load(filename):
        alpha = bytes.fromhex(vector["alpha"])
        ad = bytes.fromhex(vector["ad"])
        proof_bytes = ring_proof_bytes(vector)
        keys = RingVRF[curve].parse_keys(bytes.fromhex(vector["ring_pks"]))
        params = RingProofParams(test_vectors=True, cv=curve)
        ring = Ring(keys, params)
        ring_root = RingRoot.from_ring(ring, params)
        proof = RingVRF[curve].decode(proof_bytes)

        assert ring_root.encode().hex() == vector["ring_pks_com"]
        assert proof.verify(alpha, ad, ring, ring_root)
        generated = RingVRF[curve].prove(alpha, ad, bytes.fromhex(vector["sk"]), bytes.fromhex(vector["pk"]), ring, ring_root)
        assert generated.encode() == proof_bytes


def test_batch_verify_apis() -> None:
    vectors = load("bandersnatch_sha-512_ell2_thin.json")[:2]
    thin_proofs = [
        ThinVRF[Bandersnatch].prove(bytes.fromhex(vector["alpha"]), bytes.fromhex(vector["sk"]), bytes.fromhex(vector["ad"])) for vector in vectors
    ]
    inputs = [bytes.fromhex(vector["alpha"]) for vector in vectors]
    ads = [bytes.fromhex(vector["ad"]) for vector in vectors]
    public_keys = [bytes.fromhex(vector["pk"]) for vector in vectors]

    assert ThinVRF[Bandersnatch].batch_verify(thin_proofs, public_keys, inputs, ads)
    bad_thin = copy.copy(thin_proofs[0])
    bad_thin.s = (bad_thin.s + 1) % Bandersnatch.curve.params.subgroup_order
    assert not ThinVRF[Bandersnatch].batch_verify([bad_thin, thin_proofs[1]], public_keys, inputs, ads)

    pedersen_vectors = load("bandersnatch_sha-512_ell2_pedersen.json")[:2]
    pedersen_proofs = [
        PedersenVRF[Bandersnatch].prove(bytes.fromhex(vector["alpha"]), bytes.fromhex(vector["sk"]), bytes.fromhex(vector["ad"]))
        for vector in pedersen_vectors
    ]
    pedersen_inputs = [bytes.fromhex(vector["alpha"]) for vector in pedersen_vectors]
    pedersen_ads = [bytes.fromhex(vector["ad"]) for vector in pedersen_vectors]
    assert PedersenVRF[Bandersnatch].batch_verify(pedersen_proofs, pedersen_inputs, pedersen_ads)
    bad_pedersen = PedersenVRF[Bandersnatch](
        pedersen_proofs[0].output_point,
        pedersen_proofs[0].blinded_pk,
        pedersen_proofs[0].result_point,
        pedersen_proofs[0].ok,
        (pedersen_proofs[0].s + 1) % Bandersnatch.curve.params.subgroup_order,
        pedersen_proofs[0].sb,
    )
    assert not PedersenVRF[Bandersnatch].batch_verify([bad_pedersen, pedersen_proofs[1]], pedersen_inputs, pedersen_ads)


def test_ring_batch_verify_api(monkeypatch: pytest.MonkeyPatch) -> None:
    vector = load("bandersnatch_sha-512_ell2_ring.json")[0]
    alpha = bytes.fromhex(vector["alpha"])
    ad = bytes.fromhex(vector["ad"])
    keys = RingVRF[Bandersnatch].parse_keys(bytes.fromhex(vector["ring_pks"]))
    params = RingProofParams(test_vectors=True)
    ring = Ring(keys, params)
    ring_root = RingRoot.from_ring(ring, params)
    proof = RingVRF[Bandersnatch].decode(ring_proof_bytes(vector))
    second_alpha = b"ring-batch-second"
    second_ad = b"ring-batch-ad"
    second_proof = RingVRF[Bandersnatch].prove(second_alpha, second_ad, bytes.fromhex(vector["sk"]), bytes.fromhex(vector["pk"]), ring, ring_root)

    batch = [proof, second_proof]
    inputs = [alpha, second_alpha]
    ads = [ad, second_ad]

    def fail_single_verify(*_args: object, **_kwargs: object) -> bool:
        raise AssertionError("RingVRF.batch_verify must use batched checks")

    monkeypatch.setattr(RingVRF, "verify", fail_single_verify)
    assert RingVRF[Bandersnatch].batch_verify(batch, inputs, ads, ring, ring_root)

    bad_proof = copy.copy(second_proof)
    bad_proof.l_zeta_omega = (bad_proof.l_zeta_omega + 1) % params.prime
    assert not RingVRF[Bandersnatch].batch_verify([proof, bad_proof], inputs, ads, ring, ring_root)


def test_negative_and_malformed_proofs() -> None:
    tiny_vector = load("bandersnatch_sha-512_ell2_tiny.json")[0]
    alpha = bytes.fromhex(tiny_vector["alpha"])
    ad = bytes.fromhex(tiny_vector["ad"])
    pk = bytes.fromhex(tiny_vector["pk"])
    sk = bytes.fromhex(tiny_vector["sk"])
    tiny = TinyVRF[Bandersnatch].prove(alpha, sk, ad)

    assert not tiny.verify(pk, alpha, b"wrong-ad")
    assert not tiny.verify(pk, b"wrong-input", ad)
    with pytest.raises(ValueError, match="invalid Tiny VRF proof length"):
        TinyVRF[Bandersnatch].decode(tiny.encode()[:-1])

    thin = ThinVRF[Bandersnatch].prove(alpha, sk, ad)
    with pytest.raises(ValueError, match="invalid Thin VRF proof length"):
        ThinVRF[Bandersnatch].decode(thin.encode()[:-1])

    pedersen = PedersenVRF[Bandersnatch].prove(alpha, sk, ad)
    assert not pedersen.verify(alpha, b"wrong-ad")
    with pytest.raises(ValueError, match="invalid Pedersen VRF proof length"):
        PedersenVRF[Bandersnatch].decode(pedersen.encode()[:-1])

    ring_vector = load("bandersnatch_sha-512_ell2_ring.json")[0]
    ring_alpha = bytes.fromhex(ring_vector["alpha"])
    ring_ad = bytes.fromhex(ring_vector["ad"])
    proof_bytes = ring_proof_bytes(ring_vector)
    keys = RingVRF[Bandersnatch].parse_keys(bytes.fromhex(ring_vector["ring_pks"]))
    params = RingProofParams(test_vectors=True)
    ring = Ring(keys, params)
    ring_root = RingRoot.from_ring(ring, params)
    wrong_root = RingRoot.from_ring(Ring(list(reversed(keys)), params), params)
    proof = RingVRF[Bandersnatch].decode(proof_bytes)

    assert not proof.verify(ring_alpha, b"wrong-ad", ring, ring_root)
    assert not proof.verify(b"wrong-input", ring_ad, ring, ring_root)
    assert not proof.verify(ring_alpha, ring_ad, ring, wrong_root)
    with pytest.raises(ValueError, match="invalid Ring VRF proof length"):
        RingVRF[Bandersnatch].decode(proof_bytes[:-1])
    pedersen_len = len(proof_bytes) - len(bytes.fromhex(ring_vector["ring_proof"]))
    invalid_kzg_point = proof_bytes[:pedersen_len] + b"\xff" * 48 + proof_bytes[pedersen_len + 48 :]
    with pytest.raises(ValueError):
        RingVRF[Bandersnatch].decode(invalid_kzg_point)
    with pytest.raises(ValueError, match="invalid ring root length"):
        RingRoot.decode(ring_root.encode()[:-1])
    with pytest.raises(ValueError):
        RingRoot.decode(b"\xff" * 48 + ring_root.encode()[48:])


def test_ring_rejects_wrong_prover_key() -> None:
    vector = load("bandersnatch_sha-512_ell2_ring.json")[0]
    alpha = bytes.fromhex(vector["alpha"])
    ad = bytes.fromhex(vector["ad"])
    keys = RingVRF[Bandersnatch].parse_keys(bytes.fromhex(vector["ring_pks"]))
    params = RingProofParams(test_vectors=True)
    ring = Ring(keys, params)
    ring_root = RingRoot.from_ring(ring, params)
    wrong_secret = bytes.fromhex(load("bandersnatch_sha-512_ell2_tiny.json")[1]["sk"])
    wrong_pk = Bandersnatch.public_key_from_secret(wrong_secret)

    with pytest.raises(ValueError, match="producer key is not in ring"):
        RingVRF[Bandersnatch].prove(alpha, ad, wrong_secret, wrong_pk, ring, ring_root)
