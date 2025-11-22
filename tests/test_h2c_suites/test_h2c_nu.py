import json
import os
import pytest
from dot_ring.curve.specs.bls12_381_G1 import nu_variant as bls12_381_G1_nu_variant
from dot_ring.curve.specs.curve25519 import nu_variant as curve25519_nu_variant
from dot_ring.curve.specs.curve448 import nu_variant as curve448_nu_variant
from dot_ring.curve.specs.ed25519 import nu_variant as ed25519_nu_variant
from dot_ring.curve.specs.ed448 import nu_variant as ed448_nu_variant
from dot_ring.curve.specs.p256 import nu_variant as p256_nu_variant
from dot_ring.curve.specs.p384 import nu_variant as p384_nu_variant
from dot_ring.curve.specs.p521 import nu_variant as p521_nu_variant
from dot_ring.curve.specs.secp256k1 import nu_variant as secp256k1_nu_variant
from dot_ring.curve.e2c import E2C_Variant

HERE = os.path.dirname(__file__)

# (point_factory, json_file, byte_size, variant)
TEST_CASES = [
    (lambda: bls12_381_G1_nu_variant(E2C_Variant.SSWU_NU), "bls12_381_G1_nu.json", 48),
    (lambda: curve25519_nu_variant(E2C_Variant.ELL2_NU), "curve25519_nu.json", 32),
    (lambda: curve448_nu_variant(E2C_Variant.ELL2_NU), "curve448_nu.json", 56),
    (lambda: ed25519_nu_variant(E2C_Variant.ELL2_NU), "ed25519_nu.json", 32),
    (lambda: ed448_nu_variant(E2C_Variant.ELL2_NU), "ed448_nu.json", 56),
    (lambda: p256_nu_variant(E2C_Variant.SSWU_NU), "p256_nu.json", 32),
    (lambda: p384_nu_variant(E2C_Variant.SSWU_NU), "p384_nu.json", 48),
    (lambda: p521_nu_variant(E2C_Variant.SSWU_NU), "p521_nu.json", 66),
    (lambda: secp256k1_nu_variant(E2C_Variant.SSWU_NU), "secp256k1_nu.json", 32),
]

@pytest.mark.parametrize("point_factory, json_file, byte_size", TEST_CASES)
def test_h2c_nu(point_factory, json_file, byte_size):
    """Test hash-to-curve NU (non-uniform) variant"""
    point_class = point_factory()
    
    json_path = os.path.join(HERE, "../vectors/h2c", json_file)
    with open(json_path, "r") as f:
        data = json.load(f)
    
    vectors = data["vectors"]
    
    for i, t in enumerate(vectors, start=1):
        msg_bytes = t["msg"].encode("utf-8")
        out = point_class.encode_to_curve(msg_bytes, b"", True)
        
        u0_bytes = out["u"][0].to_bytes(byte_size, 'big').hex()
        Px_bytes = out["P"][0].to_bytes(byte_size, 'big').hex()
        Py_bytes = out["P"][1].to_bytes(byte_size, 'big').hex()
        
        assert u0_bytes == t["u"][0], f"u0 mismatch at vector {i}"
        assert Px_bytes == t["P"]["x"], f"P.x mismatch at vector {i}"
        assert Py_bytes == t["P"]["y"], f"P.y mismatch at vector {i}"
