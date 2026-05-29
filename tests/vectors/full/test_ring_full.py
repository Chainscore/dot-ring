import json
from pathlib import Path

from dot_ring.vrf.ring.ring_root import Ring, RingRoot


def test_safrole_ring_root_actual_vector() -> None:
    vector_path = Path(__file__).with_name("safrole-ring-root.json")

    vector = json.loads(vector_path.read_text())

    ring = Ring([bytes.fromhex(pk) for pk in vector["pubkeys_hex"]])

    ring_root = RingRoot.from_ring(ring)

    assert ring_root.to_bytes().hex() == vector["ring_root_hex"]


def test_gamma_z():
    expected_gamma_z = (
        "a6c2f622ccf61a6df6de4984466b9392265efb6d0fe77fe7b89ef9585291bac4263fe5227f381d0247873b52a3693c86"
        "acd94b925ac12458724358c0646159763ccc93234a896bc3ca1fd2b20ce4f58c1bbdabbe96a7eb9bd3e29cf9ab3cb0cf"
        "92e630ae2b14e758ab0960e372172203f4c9a41777dadd529971d7ab9d23ab29fe0e9c85ec450505dde7f5ac038274cf"
    )

    ring = Ring(
        [
            bytes.fromhex(pk)
            for pk in [
                "9326edb21e5541717fde24ec085000b28709847b8aab1ac51f84e94b37ca1b66",
                "0000000000000000000000000000000000000000000000000000000000000000",
                "ff71c6c03ff88adb5ed52c9681de1629a54e702fc14729f6b50d2f0a76f185b3",
                "1ecc3686b60ee3b84b6c7d321d70d5c06e9dac63a4d0a79d731b17c0d04d030d",
                "dee6d555b82024f1ccf8a1e37e60fa60fd40b1958c4bb3006af78647950e1b91",
                "0746846d17469fb2f95ef365efcab9f4e22fa1feb53111c995376be8019981cc",
            ]
        ]
    )

    ring_root = RingRoot.from_ring(ring)

    assert ring_root.to_bytes().hex() == expected_gamma_z
