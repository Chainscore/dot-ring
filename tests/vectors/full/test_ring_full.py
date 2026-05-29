import json
from pathlib import Path

import pytest

from dot_ring.vrf.ring.ring_root import Ring, RingRoot


def test_safrole_ring_root_actual_vector() -> None:
    vector_path = Path(__file__).with_name("safrole-ring-root.json")

    vector = json.loads(vector_path.read_text())

    ring = Ring([bytes.fromhex(pk) for pk in vector["pubkeys_hex"]])

    ring_root = RingRoot.from_ring(ring)

    assert ring_root.to_bytes().hex() == vector["ring_root_hex"]
