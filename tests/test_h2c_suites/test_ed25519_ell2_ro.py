import os
from dot_ring.curve.specs.ed25519 import Ed25519_TE_Curve, Ed25519Point


def test_sswu_hash2_curve():
    import json
    base_dir = os.path.dirname(__file__)  # directory of current test file
    json_path = os.path.join(base_dir, "vectors", "ed25519_ro.json")
    # Load JSON
    with open(json_path, "r") as f:
        data = json.load(f)
    RFC_TEST_VECTORS = data["vectors"]

    for i,t in enumerate(RFC_TEST_VECTORS, start=1):
        msg_bytes = t["msg"].encode("utf-8")
        out = Ed25519Point.encode_to_curve(msg_bytes, b"", True)
        u0_bytes = out["u"][0].to_bytes(32, 'big').hex()
        u1_bytes = out["u"][1].to_bytes(32, 'big').hex()
        Px_bytes = out["P"][0].to_bytes(32, 'big').hex()
        Py_bytes = out["P"][1].to_bytes(32, 'big').hex()
        Q0x_bytes=out["Q0"][0].to_bytes(32, 'big').hex()
        Q0y_bytes=out["Q0"][1].to_bytes(32, 'big').hex()
        Q1x_bytes=out["Q1"][0].to_bytes(32, 'big').hex()
        Q1y_bytes=out["Q1"][1].to_bytes(32, 'big').hex()
        assert u0_bytes==t["u"][0]
        assert u1_bytes==t["u"][1]
        assert Q0x_bytes==t["Q0"]["x"]
        assert Q0y_bytes==t["Q0"]["y"]
        assert Q1x_bytes==t["Q1"]["x"]
        assert Q1y_bytes==t["Q1"]["y"]
        assert Px_bytes==t["P"]["x"]
        assert Py_bytes==t["P"]["y"]
        print(f"✅ Testcase {i + 1}")