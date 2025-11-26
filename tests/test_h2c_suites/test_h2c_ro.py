import json
import os
import pytest
from dot_ring.curve.specs.bls12_381_G1 import BLS12_381_G1_RO
from dot_ring.curve.specs.curve25519 import Curve25519_RO
from dot_ring.curve.specs.curve448 import Curve448_RO
from dot_ring.curve.specs.ed25519 import Ed25519_RO
from dot_ring.curve.specs.ed448 import Ed448_RO
from dot_ring.curve.specs.p256 import P256_RO
from dot_ring.curve.specs.p384 import P384_RO
from dot_ring.curve.specs.p521 import P521_RO
from dot_ring.curve.specs.secp256k1 import Secp256k1_RO

HERE = os.path.dirname(__file__)

# (point_class, json_file, byte_size, has_Q_points)
TEST_CASES = [
    (BLS12_381_G1_RO.point, "bls12_381_G1_ro.json", 48, False),
    (Curve25519_RO.point, "curve25519_ro.json", 32, False),
    (Curve448_RO.point, "curve448_ro.json", 56, False),
    (Ed25519_RO.point, "ed25519_ro.json", 32, True),
    (Ed448_RO.point, "ed448_ro.json", 56, False),
    (P256_RO.point, "p256_ro.json", 32, False),
    (P384_RO.point, "p384_ro.json", 48, False),
    (P521_RO.point, "p521_ro.json", 66, False),
    (Secp256k1_RO.point, "secp256k1_ro.json", 32, False),
]

@pytest.mark.parametrize("point_class, json_file, byte_size, has_Q_points", TEST_CASES)
def test_h2c_ro(point_class, json_file, byte_size, has_Q_points):
    """Test hash-to-curve RO (random oracle) variant"""
    json_path = os.path.join(HERE, "../vectors/h2c", json_file)
    with open(json_path, "r") as f:
        data = json.load(f)
    
    vectors = data["vectors"]
    
    for i, t in enumerate(vectors, start=1):
        msg_bytes = t["msg"].encode("utf-8")
        out = point_class.encode_to_curve(msg_bytes, b"", True)
        
        u0_bytes = out["u"][0].to_bytes(byte_size, 'big').hex()
        u1_bytes = out["u"][1].to_bytes(byte_size, 'big').hex()
        Px_bytes = out["P"][0].to_bytes(byte_size, 'big').hex()
        Py_bytes = out["P"][1].to_bytes(byte_size, 'big').hex()
        
        assert u0_bytes == t["u"][0], f"u0 mismatch at vector {i}"
        assert u1_bytes == t["u"][1], f"u1 mismatch at vector {i}"
        assert Px_bytes == t["P"]["x"], f"P.x mismatch at vector {i}"
        assert Py_bytes == t["P"]["y"], f"P.y mismatch at vector {i}"
        
        if has_Q_points:
            Q0x_bytes = out["Q0"][0].to_bytes(byte_size, 'big').hex()
            Q0y_bytes = out["Q0"][1].to_bytes(byte_size, 'big').hex()
            Q1x_bytes = out["Q1"][0].to_bytes(byte_size, 'big').hex()
            Q1y_bytes = out["Q1"][1].to_bytes(byte_size, 'big').hex()
            
            assert Q0x_bytes == t["Q0"]["x"], f"Q0.x mismatch at vector {i}"
            assert Q0y_bytes == t["Q0"]["y"], f"Q0.y mismatch at vector {i}"
            assert Q1x_bytes == t["Q1"]["x"], f"Q1.x mismatch at vector {i}"
            assert Q1y_bytes == t["Q1"]["y"], f"Q1.y mismatch at vector {i}"
