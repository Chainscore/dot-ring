import os
from dot_ring.curve.specs.p384 import nu_variant
from dot_ring.curve.e2c import E2C_Variant
P384Point=nu_variant(E2C_Variant.SSWU_NU)
def test_sswu_hash2_curve():
    import json
    base_dir = os.path.dirname(__file__)  # directory of current test file
    json_path = os.path.join(base_dir, "vectors", "p384_nu.json")
    # Load JSON
    with open(json_path, "r") as f:
        data = json.load(f)
    RFC_TEST_VECTORS = data["vectors"]
    for i, t in enumerate(RFC_TEST_VECTORS, start=1):
        msg_bytes = t["msg"].encode("utf-8")
        out = P384Point.encode_to_curve(msg_bytes, b"", True)
        u0_bytes = out["u"][0].to_bytes(48, 'big').hex()
        Px_bytes = out["P"][0].to_bytes(48, 'big').hex()
        Py_bytes = out["P"][1].to_bytes(48, 'big').hex()
        assert u0_bytes==t["u"][0]
        assert Px_bytes==t["P"]["x"]
        assert Py_bytes==t["P"]["y"]
        print(f"✅ Testcase {i + 1}")


