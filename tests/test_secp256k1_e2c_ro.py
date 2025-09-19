
from dot_ring.curve.specs.secp256k1 import (Secp256k1_SW_Curve, Secp256k1Point)

def test_sswu_hash2_curve():
    import json
    json_path = "/home/siva/PycharmProjects/DT/dot_ring/tests/vectors/secp256k1_ro.json"
    # Load JSON
    with open(json_path, "r") as f:
        data = json.load(f)
    RFC_TEST_VECTORS = data["vectors"]
    for t in RFC_TEST_VECTORS:
        msg_bytes = t["msg"].encode("utf-8")
        out = Secp256k1Point.encode_to_curve(msg_bytes, b"", True)
        u0_bytes = out["u"][0].to_bytes(32, 'big').hex()
        u1_bytes = out["u"][1].to_bytes(32, 'big').hex()
        Px_bytes = out["P"][0].to_bytes(32, 'big').hex()
        Py_bytes = out["P"][1].to_bytes(32, 'big').hex()
        print("msg:", repr(t["msg"]))
        print(" computed u[0] =", u0_bytes)
        print(" expected u[0] =", t["u"][0])
        print(" computed u[1] =", u1_bytes)
        print(" expected u[1] =", t["u"][1])
        print(" computed P.x =", Px_bytes)
        print(" expected P.x =", t["P"]["x"])
        print(" computed P.y =", Py_bytes)
        print(" expected P.y =", t["P"]["y"])

