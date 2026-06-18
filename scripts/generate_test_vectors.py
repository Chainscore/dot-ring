#!/usr/bin/env python3
"""Generate dot-ring vectors using canonical JSON fields."""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from dot_ring.curve.curve import CurveVariant
from dot_ring.curve.specs.baby_jubjub import BabyJubJub
from dot_ring.curve.specs.bandersnatch import Bandersnatch, Bandersnatch_SHAKE128
from dot_ring.curve.specs.bandersnatch_sw import Bandersnatch_SW
from dot_ring.curve.specs.ed25519 import Ed25519_TAI
from dot_ring.curve.specs.jubjub import JubJub
from dot_ring.curve.specs.p256 import P256_TAI
from dot_ring.keygen import secret_from_seed
from dot_ring.ring_proof.params import RingProofParams
from dot_ring.vrf.ietf import ThinVRF, TinyVRF
from dot_ring.vrf.pedersen import PedersenVRF
from dot_ring.vrf.ring import Ring, RingRoot, RingVRF
from dot_ring.vrf.transcript import point_len, scalar_encode, scalar_len

DEFAULT_OUT_DIR = Path(__file__).resolve().parent.parent / "tests" / "vectors" / "dot-ring"
RING_SIZE = 8
PROVER_INDEX = 3


@dataclass(frozen=True)
class Suite:
    prefix: str
    curve: CurveVariant


SUITES = [
    Suite("bandersnatch_sha-512_ell2", Bandersnatch),
    Suite("bandersnatch_sw_sha-512_tai", Bandersnatch_SW),
    Suite("bandersnatch_shake128_ell2", Bandersnatch_SHAKE128),
    Suite("ed25519_sha-512_tai", Ed25519_TAI),
    Suite("secp256r1_sha-256_tai", P256_TAI),
    Suite("jubjub_sha-512_tai", JubJub),
    Suite("baby-jubjub_sha-512_tai", BabyJubJub),
]

RING_SUITES = [
    Suite("bandersnatch_sha-512_ell2", Bandersnatch),
    Suite("bandersnatch_sw_sha-512_tai", Bandersnatch_SW),
    Suite("bandersnatch_shake128_ell2", Bandersnatch_SHAKE128),
    Suite("jubjub_sha-512_tai", JubJub),
]

VECTOR_CASES = [
    (1, b"", b""),
    (2, bytes.fromhex("0a"), b""),
    (3, b"", bytes.fromhex("0b8c")),
    (4, bytes.fromhex("73616D706C65"), b""),
    (5, bytes.fromhex("42616E646572736E6174636820766563746F72"), b""),
    (5, bytes.fromhex("42616E646572736E6174636820766563746F72"), bytes.fromhex("1F42")),
    (6, bytes.fromhex("42616E646572736E6174636820766563746F72"), bytes.fromhex("1F42")),
]


def seed_bytes(seed: int) -> bytes:
    seed_value = bytearray(32)
    seed_value[0] = seed
    return bytes(seed_value)


def pedersen_len(curve: CurveVariant) -> int:
    return 4 * point_len(curve) + 2 * scalar_len(curve)


def base_fields(suite: Suite, scheme: str, index: int, seed: int, alpha: bytes, ad: bytes) -> tuple[bytes, dict[str, str]]:
    pk, sk = secret_from_seed(seed_bytes(seed), suite.curve)
    input_point = suite.curve.encode_to_curve(alpha)
    gamma = input_point * int.from_bytes(sk, "little")
    beta = TinyVRF[suite.curve].proof_to_hash(gamma)
    return sk, {
        "comment": f"{suite.prefix}_{scheme} - vector-{index}",
        "sk": sk.hex(),
        "pk": pk.hex(),
        "alpha": alpha.hex(),
        "ad": ad.hex(),
        "h": input_point.point_to_string().hex(),
        "gamma": gamma.point_to_string().hex(),
        "beta": beta.hex(),
    }


def tiny_vector(suite: Suite, index: int, seed: int, alpha: bytes, ad: bytes) -> dict[str, str]:
    sk, vector = base_fields(suite, "tiny", index, seed, alpha, ad)
    proof = TinyVRF[suite.curve].prove(alpha, sk, ad)
    vector.update(
        {
            "proof_c": proof.c.to_bytes(16, "little").hex(),
            "proof_s": scalar_encode(suite.curve, proof.s).hex(),
        }
    )
    return vector


def thin_vector(suite: Suite, index: int, seed: int, alpha: bytes, ad: bytes) -> dict[str, str]:
    sk, vector = base_fields(suite, "thin", index, seed, alpha, ad)
    proof = ThinVRF[suite.curve].prove(alpha, sk, ad)
    vector.update(
        {
            "proof_r": proof.r.point_to_string().hex(),
            "proof_s": scalar_encode(suite.curve, proof.s).hex(),
        }
    )
    return vector


def pedersen_vector(suite: Suite, index: int, seed: int, alpha: bytes, ad: bytes) -> dict[str, str]:
    sk, vector = base_fields(suite, "pedersen", index, seed, alpha, ad)
    proof = PedersenVRF[suite.curve].prove(alpha, sk, ad)
    vector.update(
        {
            "blinding": scalar_encode(suite.curve, proof._blinding_factor).hex(),
            "proof_pk_com": proof.blinded_pk.point_to_string().hex(),
            "proof_r": proof.result_point.point_to_string().hex(),
            "proof_ok": proof.ok.point_to_string().hex(),
            "proof_s": scalar_encode(suite.curve, proof.s).hex(),
            "proof_sb": scalar_encode(suite.curve, proof.sb).hex(),
        }
    )
    return vector


def ring_keys(
    suite: Suite,
    seed: int,
    prover_pk: bytes,
    ring_size: int = RING_SIZE,
    prover_index: int = PROVER_INDEX,
) -> list[bytes]:
    keys = []
    for idx in range(ring_size):
        if idx == prover_index:
            keys.append(prover_pk)
        else:
            other_pk, _ = secret_from_seed(seed_bytes(0x11 + idx * 0x10 + seed), suite.curve)
            keys.append(other_pk)
    return keys


def ring_vector(suite: Suite, index: int, seed: int, alpha: bytes, ad: bytes) -> dict[str, Any]:
    sk, vector = base_fields(suite, "ring", index, seed, alpha, ad)
    producer_pk = bytes.fromhex(vector["pk"])
    keys = ring_keys(suite, seed, producer_pk)
    params = RingProofParams(test_vectors=True, cv=suite.curve)
    ring = Ring(keys, params)
    ring_root = RingRoot.from_ring(ring, params)
    proof = RingVRF[suite.curve].prove(alpha, ad, sk, producer_pk, ring, ring_root)
    pedersen = proof.pedersen_proof
    if pedersen is None:
        raise RuntimeError("ring proof did not include a Pedersen proof")

    proof_bytes = proof.to_bytes()
    vector.update(
        {
            "blinding": scalar_encode(suite.curve, pedersen._blinding_factor).hex(),
            "proof_pk_com": pedersen.blinded_pk.point_to_string().hex(),
            "proof_r": pedersen.result_point.point_to_string().hex(),
            "proof_ok": pedersen.ok.point_to_string().hex(),
            "proof_s": scalar_encode(suite.curve, pedersen.s).hex(),
            "proof_sb": scalar_encode(suite.curve, pedersen.sb).hex(),
            "ring_pks": b"".join(keys).hex(),
            "ring_pks_com": ring_root.to_bytes().hex(),
            "ring_proof": proof_bytes[pedersen_len(suite.curve) :].hex(),
            "ring_size": RING_SIZE,
            "prover_idx": PROVER_INDEX,
        }
    )
    return vector


def scheme_vectors(suite: Suite, scheme: str) -> list[dict[str, Any]]:
    builders = {
        "tiny": tiny_vector,
        "thin": thin_vector,
        "pedersen": pedersen_vector,
        "ring": ring_vector,
    }
    return [builders[scheme](suite, index, seed, alpha, ad) for index, (seed, alpha, ad) in enumerate(VECTOR_CASES, start=1)]


def write_vectors(out_dir: Path, suite: Suite, scheme: str) -> None:
    vectors = scheme_vectors(suite, scheme)
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{suite.prefix}_{scheme}.json"
    path.write_text(json.dumps(vectors, indent=2))
    print(f"wrote {path}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
    args = parser.parse_args()

    for suite in SUITES:
        for scheme in ("tiny", "thin", "pedersen"):
            write_vectors(args.out_dir, suite, scheme)

    for suite in RING_SUITES:
        write_vectors(args.out_dir, suite, "ring")


if __name__ == "__main__":
    main()
