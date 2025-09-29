import os
from dot_ring.curve.specs.curve25519 import nu_variant
from dot_ring.curve.e2c import E2C_Variant


def test_sswu_hash2_curve():
    import json
    base_dir = os.path.dirname(__file__)  # directory of current test file
    json_path = os.path.join(base_dir, "vectors", "curve25519_nu.json")
    # Load JSON
    with open(json_path, "r") as f:
        data = json.load(f)
    RFC_TEST_VECTORS = data["vectors"]
    
    # Simple one-liner to get point class with NU variant 
    Curve25519Point= nu_variant(E2C_Variant.ELL2_NU)
    
    for i, t in enumerate(RFC_TEST_VECTORS, start=1):
        msg_bytes = t["msg"].encode("utf-8")
        # Use the NU point class
        out = Curve25519Point.encode_to_curve(msg_bytes, b"", True)
        u0_bytes = out["u"][0].to_bytes(32, 'big').hex()
        Px_bytes = out["P"][0].to_bytes(32, 'big').hex()
        Py_bytes = out["P"][1].to_bytes(32, 'big').hex()
        assert u0_bytes == t["u"][0]
        assert Px_bytes == t["P"]["x"]
        assert Py_bytes == t["P"]["y"]
        print(f" Testcase {i + 1}")