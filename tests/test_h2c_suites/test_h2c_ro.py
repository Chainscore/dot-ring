import json
import os

import pytest

from dot_ring.curve.specs.bls12_381_G1 import BLS12_381_G1_RO
from dot_ring.curve.specs.curve448 import Curve448_RO
from dot_ring.curve.specs.curve25519 import Curve25519_RO
from dot_ring.curve.specs.ed448 import Ed448_RO
from dot_ring.curve.specs.ed25519 import Ed25519_RO
from dot_ring.curve.specs.p256 import P256_RO
from dot_ring.curve.specs.p384 import P384_RO
from dot_ring.curve.specs.p521 import P521_RO
from dot_ring.curve.specs.secp256k1 import Secp256k1_RO

HERE = os.path.dirname(__file__)

# (curve_variant, json_file, byte_size)
TEST_CASES = [
    (BLS12_381_G1_RO, "bls12_381_G1_ro.json", 48),
    (Curve25519_RO, "curve25519_ro.json", 32),
    (Curve448_RO, "curve448_ro.json", 56),
    (Ed25519_RO, "ed25519_ro.json", 32),
    (Ed448_RO, "ed448_ro.json", 56),
    (P256_RO, "p256_ro.json", 32),
    (P384_RO, "p384_ro.json", 48),
    (P521_RO, "p521_ro.json", 66),
    (Secp256k1_RO, "secp256k1_ro.json", 32),
]


@pytest.mark.parametrize("curve_variant, json_file, byte_size", TEST_CASES)
def test_h2c_ro(curve_variant, json_file, byte_size):
    """Test hash-to-curve RO (random oracle) variant"""
    json_path = os.path.join(HERE, "../vectors/h2c", json_file)
    with open(json_path) as f:
        data = json.load(f)

    vectors = data["vectors"]

    for i, t in enumerate(vectors, start=1):
        msg_bytes = t["msg"].encode("utf-8")
        point = curve_variant.point_type.encode_to_curve(msg_bytes, b"")

        Px_bytes = point.x.to_bytes(byte_size, "big").hex()
        Py_bytes = point.y.to_bytes(byte_size, "big").hex()

        assert Px_bytes == t["P"]["x"], f"P.x mismatch at vector {i}"
        assert Py_bytes == t["P"]["y"], f"P.y mismatch at vector {i}"
