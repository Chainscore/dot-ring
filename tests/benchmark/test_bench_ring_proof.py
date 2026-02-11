import sys
from pathlib import Path

import pytest

# Add blst to path if needed
sys.path.insert(0, str(Path(__file__).parent.parent / "dot_ring" / "blst" / "bindings" / "python"))

from dot_ring import Bandersnatch
from dot_ring.vrf.ring.ring_root import Ring, RingRoot
from dot_ring.vrf.ring.ring_vrf import RingVRF


# MAX_RING_SIZE is 255 per the constraint system
@pytest.fixture(scope="module", params=[255])
def ring_data(request):
    ring_size = request.param

    s_k = b"secret_key_seed" * 2
    s_k = s_k[:32]
    p_k = RingVRF[Bandersnatch].get_public_key(s_k)

    keys = [p_k]
    for i in range(ring_size - 1):
        sk_i = (int.from_bytes(s_k, "little") + i + 1).to_bytes(32, "little")
        pk_i = RingVRF[Bandersnatch].get_public_key(sk_i)
        keys.append(pk_i)

    alpha = b"test_message"
    ad = b"test_ad"

    ring = Ring(keys)
    ring_root = RingRoot.from_ring(ring, ring.params)

    # Pre-calculate a proof for verification benchmark
    proof = RingVRF[Bandersnatch].prove(alpha, ad, s_k, p_k, ring, ring_root)

    return {"s_k": s_k, "p_k": p_k, "ring": ring, "alpha": alpha, "ad": ad, "ring_root": ring_root, "proof": proof}


def test_prove(benchmark, ring_data):
    benchmark(
        RingVRF[Bandersnatch].prove, 
        ring_data["alpha"], 
        ring_data["ad"], 
        ring_data["s_k"], 
        ring_data["p_k"], 
        ring_data["ring"], 
        ring_data["ring_root"]
    )


def test_verify(benchmark, ring_data):
    benchmark(ring_data["proof"].verify, ring_data["alpha"], ring_data["ad"], ring_data["ring"], ring_data["ring_root"])
