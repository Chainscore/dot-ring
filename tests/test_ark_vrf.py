import copy
import json
from pathlib import Path

import pytest

from dot_ring.curve.specs.baby_jubjub import BabyJubJub
from dot_ring.curve.specs.bandersnatch import Bandersnatch, Bandersnatch_SHAKE128
from dot_ring.curve.specs.bandersnatch_sw import Bandersnatch_SW
from dot_ring.curve.specs.ed25519 import Ed25519_NU
from dot_ring.curve.specs.jubjub import JubJub
from dot_ring.curve.specs.p256 import P256_NU
from dot_ring.ring_proof.params import RingProofParams
from dot_ring.vrf.ietf.ietf import ThinBatchVerifier, ThinVRF, TinyVRF
from dot_ring.vrf.pedersen.pedersen import PedersenBatchVerifier, PedersenVRF
from dot_ring.vrf.ring.ring_root import Ring, RingRoot
from dot_ring.vrf.ring.ring_vrf import RingBatchVerifier, RingContext, RingVRF
from dot_ring.vrf.transcript import VrfIo
from scripts.generate_test_vectors import SUITES as GENERATED_SUITES
from scripts.generate_test_vectors import scheme_vectors

VECTORS = Path(__file__).parent / "vectors" / "ark-vrf"

SUITES = [
    (Bandersnatch, "bandersnatch_sha-512_ell2", 32),
    (Bandersnatch_SW, "bandersnatch_sw_sha-512_tai", 33),
    (Bandersnatch_SHAKE128, "bandersnatch_shake128_ell2", 32),
    (Ed25519_NU, "ed25519_sha-512_tai", 32),
    (P256_NU, "secp256r1_sha-256_tai", 33),
    (JubJub, "jubjub_sha-512_tai", 32),
    (BabyJubJub, "baby-jubjub_sha-512_tai", 32),
]


def load(name: str) -> list[dict[str, str]]:
    return json.loads((VECTORS / name).read_text())


def ring_proof_bytes(vector: dict[str, str]) -> bytes:
    return bytes.fromhex(
        vector["gamma"]
        + vector["proof_pk_com"]
        + vector["proof_r"]
        + vector["proof_ok"]
        + vector["proof_s"]
        + vector["proof_sb"]
        + vector["ring_proof"]
    )


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
        proof_bytes = proof.to_bytes()

        assert TinyVRF[curve].get_public_key(sk).hex() == vector["pk"]
        assert curve.point.encode_to_curve(alpha).point_to_string().hex() == vector["h"]
        assert proof_bytes.hex() == vector["gamma"] + vector["proof_c"] + vector["proof_s"]
        assert TinyVRF[curve].proof_to_hash(proof.output_point).hex() == vector["beta"]
        assert proof.verify(bytes.fromhex(vector["pk"]), alpha, ad)
        assert TinyVRF[curve].from_bytes(proof_bytes).to_bytes() == proof_bytes
        assert len(proof.output_point.point_to_string()) == point_len


@pytest.mark.parametrize("curve,prefix,_point_len", SUITES)
def test_thin_vectors(curve, prefix: str, _point_len: int) -> None:
    for vector in load(f"{prefix}_thin.json"):
        sk = bytes.fromhex(vector["sk"])
        alpha = bytes.fromhex(vector["alpha"])
        ad = bytes.fromhex(vector["ad"])
        proof = ThinVRF[curve].prove(alpha, sk, ad)
        proof_bytes = proof.to_bytes()

        assert proof_bytes.hex() == vector["gamma"] + vector["proof_r"] + vector["proof_s"]
        assert proof.verify(bytes.fromhex(vector["pk"]), alpha, ad)
        assert ThinVRF[curve].from_bytes(proof_bytes).to_bytes() == proof_bytes


@pytest.mark.parametrize("curve,prefix,_point_len", SUITES)
def test_pedersen_vectors(curve, prefix: str, _point_len: int) -> None:
    for vector in load(f"{prefix}_pedersen.json"):
        sk = bytes.fromhex(vector["sk"])
        alpha = bytes.fromhex(vector["alpha"])
        ad = bytes.fromhex(vector["ad"])
        proof = PedersenVRF[curve].prove(alpha, sk, ad)
        proof_bytes = proof.to_bytes()

        assert proof_bytes.hex() == (
            vector["gamma"]
            + vector["proof_pk_com"]
            + vector["proof_r"]
            + vector["proof_ok"]
            + vector["proof_s"]
            + vector["proof_sb"]
        )
        assert proof.verify(alpha, ad)
        assert PedersenVRF[curve].from_bytes(proof_bytes).to_bytes() == proof_bytes


@pytest.mark.parametrize("curve,prefix,point_len", SUITES)
def test_rejects_invalid_point_encodings(curve, prefix: str, point_len: int) -> None:
    invalid_point = b"\xff" * point_len

    tiny_vector = load(f"{prefix}_tiny.json")[0]
    tiny_bytes = invalid_point + bytes.fromhex(tiny_vector["proof_c"] + tiny_vector["proof_s"])
    with pytest.raises(ValueError, match="INVALID|Invalid"):
        TinyVRF[curve].from_bytes(tiny_bytes)

    thin_vector = load(f"{prefix}_thin.json")[0]
    thin_bytes = invalid_point + bytes.fromhex(thin_vector["proof_r"] + thin_vector["proof_s"])
    with pytest.raises(ValueError, match="INVALID|Invalid"):
        ThinVRF[curve].from_bytes(thin_bytes)

    pedersen_vector = load(f"{prefix}_pedersen.json")[0]
    pedersen_bytes = invalid_point + bytes.fromhex(
        pedersen_vector["proof_pk_com"]
        + pedersen_vector["proof_r"]
        + pedersen_vector["proof_ok"]
        + pedersen_vector["proof_s"]
        + pedersen_vector["proof_sb"]
    )
    with pytest.raises(ValueError, match="INVALID|Invalid"):
        PedersenVRF[curve].from_bytes(pedersen_bytes)


@pytest.mark.parametrize(
    "curve,filename",
    [
        (Bandersnatch, "bandersnatch_sha-512_ell2_ring.json"),
        (Bandersnatch_SW, "bandersnatch_sw_sha-512_tai_ring.json"),
        (Bandersnatch_SHAKE128, "bandersnatch_shake128_ell2_ring.json"),
        (JubJub, "jubjub_sha-512_tai_ring.json"),
        (BabyJubJub, "baby-jubjub_sha-512_tai_ring.json"),
    ],
)
def test_ring_vectors(curve, filename: str) -> None:
    for vector in load(filename):
        alpha = bytes.fromhex(vector["alpha"])
        ad = bytes.fromhex(vector["ad"])
        proof_bytes = bytes.fromhex(
            vector["gamma"]
            + vector["proof_pk_com"]
            + vector["proof_r"]
            + vector["proof_ok"]
            + vector["proof_s"]
            + vector["proof_sb"]
            + vector["ring_proof"]
        )
        keys = RingVRF[curve].parse_keys(bytes.fromhex(vector["ring_pks"]))
        params = RingProofParams(test_vectors=True, cv=curve)
        ring = Ring(keys, params)
        ring_root = RingRoot.from_ring(ring, params)
        proof = RingVRF[curve].from_bytes(proof_bytes)

        assert ring_root.to_bytes().hex() == vector["ring_pks_com"]
        assert proof.verify(alpha, ad, ring, ring_root)
        generated = RingVRF[curve].prove(alpha, ad, bytes.fromhex(vector["sk"]), bytes.fromhex(vector["pk"]), ring, ring_root)
        assert generated.to_bytes() == proof_bytes


def test_multi_input_apis() -> None:
    secret = bytes.fromhex(load("bandersnatch_sha-512_ell2_tiny.json")[0]["sk"])
    public_key = TinyVRF[Bandersnatch].get_public_key(secret)
    secret_scalar = int.from_bytes(secret, "little")
    public_key_point = Bandersnatch.point.string_to_point(public_key)
    assert not isinstance(public_key_point, str)

    ios = []
    for alpha in (b"first", b"second"):
        input_point = Bandersnatch.point.encode_to_curve(alpha)
        ios.append(VrfIo(input_point, input_point * secret_scalar))

    tiny = TinyVRF[Bandersnatch].prove_ios(ios, secret_scalar, public_key_point, b"ad")
    thin = ThinVRF[Bandersnatch].prove_ios(ios, secret_scalar, public_key_point, b"ad")
    pedersen = PedersenVRF[Bandersnatch].prove_ios(ios, secret_scalar, public_key_point, b"ad")

    assert tiny.verify_ios(public_key_point, ios, b"ad")
    assert thin.verify_ios(public_key_point, ios, b"ad")
    assert pedersen.verify_ios(ios, b"ad")


def test_batch_apis() -> None:
    vectors = load("bandersnatch_sha-512_ell2_thin.json")[:2]
    thin_batch = ThinBatchVerifier[Bandersnatch]()
    pedersen_batch = PedersenBatchVerifier[Bandersnatch]()

    for vector in vectors:
        alpha = bytes.fromhex(vector["alpha"])
        ad = bytes.fromhex(vector["ad"])
        pk_point = Bandersnatch.point.string_to_point(bytes.fromhex(vector["pk"]))
        assert not isinstance(pk_point, str)
        thin = ThinVRF[Bandersnatch].prove(alpha, bytes.fromhex(vector["sk"]), ad)
        input_point = Bandersnatch.point.encode_to_curve(alpha)
        thin_batch.push(pk_point, [VrfIo(input_point, thin.output_point)], ad, thin)

        pedersen = PedersenVRF[Bandersnatch].prove(alpha, bytes.fromhex(vector["sk"]), ad)
        pedersen_batch.push([VrfIo(input_point, pedersen.output_point)], ad, pedersen)

    assert thin_batch.verify()
    assert pedersen_batch.verify()


def test_batch_rejects_invalid_items() -> None:
    vector = load("bandersnatch_sha-512_ell2_thin.json")[0]
    alpha = bytes.fromhex(vector["alpha"])
    ad = bytes.fromhex(vector["ad"])
    secret = bytes.fromhex(vector["sk"])
    pk_point = Bandersnatch.point.string_to_point(bytes.fromhex(vector["pk"]))
    assert not isinstance(pk_point, str)
    input_point = Bandersnatch.point.encode_to_curve(alpha)

    thin = ThinVRF[Bandersnatch].prove(alpha, secret, ad)
    bad_thin = ThinVRF[Bandersnatch](thin.output_point, thin.r, (thin.s + 1) % Bandersnatch.curve.ORDER)
    thin_batch = ThinBatchVerifier[Bandersnatch]()
    thin_batch.push(pk_point, [VrfIo(input_point, bad_thin.output_point)], ad, bad_thin)
    assert not thin_batch.verify()

    pedersen = PedersenVRF[Bandersnatch].prove(alpha, secret, ad)
    bad_pedersen = PedersenVRF[Bandersnatch](
        pedersen.output_point,
        pedersen.blinded_pk,
        pedersen.result_point,
        pedersen.ok,
        (pedersen.s + 1) % Bandersnatch.curve.ORDER,
        pedersen.sb,
    )
    pedersen_batch = PedersenBatchVerifier[Bandersnatch]()
    pedersen_batch.push([VrfIo(input_point, bad_pedersen.output_point)], ad, bad_pedersen)
    assert not pedersen_batch.verify()


def test_ring_batch_same_ring_and_invalid_item() -> None:
    vector = load("bandersnatch_sha-512_ell2_ring.json")[0]
    alpha = bytes.fromhex(vector["alpha"])
    ad = bytes.fromhex(vector["ad"])
    keys = RingVRF[Bandersnatch].parse_keys(bytes.fromhex(vector["ring_pks"]))
    params = RingProofParams(test_vectors=True)
    ring = Ring(keys, params)
    ring_root = RingRoot.from_ring(ring, params)
    proof = RingVRF[Bandersnatch].from_bytes(ring_proof_bytes(vector))
    second_alpha = b"ring-batch-second"
    second_ad = b"ring-batch-ad"
    second_proof = RingVRF[Bandersnatch].prove(
        second_alpha,
        second_ad,
        bytes.fromhex(vector["sk"]),
        bytes.fromhex(vector["pk"]),
        ring,
        ring_root,
    )

    batch = RingBatchVerifier()
    batch.push(proof, alpha, ad, ring, ring_root)
    batch.push(second_proof, second_alpha, second_ad, ring, ring_root)
    assert batch.verify()

    bad_proof = copy.copy(second_proof)
    bad_proof.l_zeta_omega = (bad_proof.l_zeta_omega + 1) % params.prime
    bad_batch = RingBatchVerifier()
    bad_batch.push(proof, alpha, ad, ring, ring_root)
    bad_batch.push(bad_proof, second_alpha, second_ad, ring, ring_root)
    assert not bad_batch.verify()


def test_ring_batch_multi_ring_shared_srs(monkeypatch: pytest.MonkeyPatch) -> None:
    vectors = load("bandersnatch_sha-512_ell2_ring.json")[:2]
    batch = RingBatchVerifier()

    for vector in vectors:
        keys = RingVRF[Bandersnatch].parse_keys(bytes.fromhex(vector["ring_pks"]))
        params = RingProofParams(test_vectors=True)
        ring = Ring(keys, params)
        ring_root = RingRoot.from_ring(ring, params)
        proof = RingVRF[Bandersnatch].from_bytes(ring_proof_bytes(vector))
        batch.push(proof, bytes.fromhex(vector["alpha"]), bytes.fromhex(vector["ad"]), ring, ring_root)

    def fail_single_verify(*_args: object, **_kwargs: object) -> bool:
        raise AssertionError("RingBatchVerifier must use batched checks")

    monkeypatch.setattr(RingVRF, "verify", fail_single_verify)
    assert batch.verify()


def test_ring_context_helpers() -> None:
    vector = load("bandersnatch_sha-512_ell2_ring.json")[0]
    keys_blob = bytes.fromhex(vector["ring_pks"])
    context = RingContext(RingProofParams(test_vectors=True))

    ring = context.ring(keys_blob)
    ring_root = context.verifier_key(ring)
    builder = context.verifier_key_builder()
    builder.extend(keys_blob)

    assert ring_root.to_bytes().hex() == vector["ring_pks_com"]
    assert context.ring_root(keys_blob).to_bytes() == ring_root.to_bytes()
    assert context.verifier_key_from_commitment(ring_root.to_bytes()).to_bytes() == ring_root.to_bytes()
    assert builder.finalize().to_bytes() == ring_root.to_bytes()


def test_negative_and_malformed_proofs() -> None:
    tiny_vector = load("bandersnatch_sha-512_ell2_tiny.json")[0]
    alpha = bytes.fromhex(tiny_vector["alpha"])
    ad = bytes.fromhex(tiny_vector["ad"])
    pk = bytes.fromhex(tiny_vector["pk"])
    sk = bytes.fromhex(tiny_vector["sk"])
    tiny = TinyVRF[Bandersnatch].prove(alpha, sk, ad)

    pk_point = Bandersnatch.point.string_to_point(pk)
    assert not isinstance(pk_point, str)
    wrong_output = Bandersnatch.point.encode_to_curve(b"wrong-output")

    assert not tiny.verify(pk, alpha, b"wrong-ad")
    assert not tiny.verify(pk, b"wrong-input", ad)
    assert not tiny.verify_ios(pk_point, [VrfIo(Bandersnatch.point.encode_to_curve(alpha), wrong_output)], ad)
    with pytest.raises(ValueError, match="invalid Tiny VRF proof length"):
        TinyVRF[Bandersnatch].from_bytes(tiny.to_bytes()[:-1])

    thin = ThinVRF[Bandersnatch].prove(alpha, sk, ad)
    with pytest.raises(ValueError, match="invalid Thin VRF proof length"):
        ThinVRF[Bandersnatch].from_bytes(thin.to_bytes()[:-1])

    pedersen = PedersenVRF[Bandersnatch].prove(alpha, sk, ad)
    assert not pedersen.verify(alpha, b"wrong-ad")
    with pytest.raises(ValueError, match="invalid Pedersen VRF proof length"):
        PedersenVRF[Bandersnatch].from_bytes(pedersen.to_bytes()[:-1])

    ring_vector = load("bandersnatch_sha-512_ell2_ring.json")[0]
    ring_alpha = bytes.fromhex(ring_vector["alpha"])
    ring_ad = bytes.fromhex(ring_vector["ad"])
    proof_bytes = bytes.fromhex(
        ring_vector["gamma"]
        + ring_vector["proof_pk_com"]
        + ring_vector["proof_r"]
        + ring_vector["proof_ok"]
        + ring_vector["proof_s"]
        + ring_vector["proof_sb"]
        + ring_vector["ring_proof"]
    )
    keys = RingVRF[Bandersnatch].parse_keys(bytes.fromhex(ring_vector["ring_pks"]))
    params = RingProofParams(test_vectors=True)
    ring = Ring(keys, params)
    ring_root = RingRoot.from_ring(ring, params)
    wrong_root = RingRoot.from_ring(Ring(list(reversed(keys)), params), params)
    proof = RingVRF[Bandersnatch].from_bytes(proof_bytes)

    assert not proof.verify(ring_alpha, b"wrong-ad", ring, ring_root)
    assert not proof.verify(b"wrong-input", ring_ad, ring, ring_root)
    assert not proof.verify(ring_alpha, ring_ad, ring, wrong_root)
    with pytest.raises(ValueError, match="invalid Ring VRF proof length"):
        RingVRF[Bandersnatch].from_bytes(proof_bytes[:-1])
    pedersen_len = len(proof_bytes) - len(bytes.fromhex(ring_vector["ring_proof"]))
    invalid_kzg_point = proof_bytes[:pedersen_len] + b"\xff" * 48 + proof_bytes[pedersen_len + 48 :]
    with pytest.raises(ValueError):
        RingVRF[Bandersnatch].from_bytes(invalid_kzg_point)
    with pytest.raises(ValueError, match="invalid Ring VRF proof length"):
        RingVRF[Bandersnatch].from_bytes(bytes.fromhex(ring_vector["ring_proof"])[:-1], skip_pedersen=True)
    with pytest.raises(ValueError, match="invalid ring root length"):
        RingRoot.from_bytes(ring_root.to_bytes()[:-1])
    with pytest.raises(ValueError):
        RingRoot.from_bytes(b"\xff" * 48 + ring_root.to_bytes()[48:])


def test_ring_rejects_wrong_prover_key() -> None:
    vector = load("bandersnatch_sha-512_ell2_ring.json")[0]
    alpha = bytes.fromhex(vector["alpha"])
    ad = bytes.fromhex(vector["ad"])
    keys = RingVRF[Bandersnatch].parse_keys(bytes.fromhex(vector["ring_pks"]))
    params = RingProofParams(test_vectors=True)
    ring = Ring(keys, params)
    ring_root = RingRoot.from_ring(ring, params)
    wrong_secret = bytes.fromhex(load("bandersnatch_sha-512_ell2_tiny.json")[1]["sk"])
    wrong_pk = TinyVRF[Bandersnatch].get_public_key(wrong_secret)

    with pytest.raises(ValueError, match="producer key is not in ring"):
        RingVRF[Bandersnatch].prove(alpha, ad, wrong_secret, wrong_pk, ring, ring_root)
