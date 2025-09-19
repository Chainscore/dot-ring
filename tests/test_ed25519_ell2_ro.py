
from dot_ring.curve.specs.ed25519 import Ed25519_TE_Curve, Ed25519Point


def test_sswu_hash2_curve():
    import json
    json_path = "/home/siva/PycharmProjects/DT/dot_ring/tests/vectors/ed25519_ro.json"
    # Load JSON
    with open(json_path, "r") as f:
        data = json.load(f)
    RFC_TEST_VECTORS = data["vectors"]

    for t in RFC_TEST_VECTORS:
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
        print("msg:", repr(t["msg"]))
        print(" computed u[0] =", u0_bytes)
        print(" expected u[0] =", t["u"][0])
        print(" computed u[1] =", u1_bytes)
        print(" expected u[1] =", t["u"][1])
        print("computed Q0.x =", Q0x_bytes)
        print("expected Q0.x =", t["Q0"]["x"])
        print("computed Q0.y =", Q0y_bytes)
        print("expected Q0.y =", t["Q0"]["y"])
        print("computed Q1.x =", Q1x_bytes)
        print("expected Q1.x =", t["Q1"]["x"])
        print("computed Q1.y =", Q1y_bytes)
        print("expected Q1.y =", t["Q1"]["y"])
        print(" computed P.x =", Px_bytes)
        print(" expected P.x =", t["P"]["x"])
        print(" computed P.y =", Py_bytes)
        print(" expected P.y =", t["P"]["y"])