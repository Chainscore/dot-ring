import time
import pytest
import json
import os
start_time=time.time()
from dot_ring.vrf.ring.ring_vrf import RingVrf as RVRF
HERE = os.path.dirname(__file__)

# Try to import the local blst Python bindings
try:
    import blst
    HAS_BLST = True
except ImportError:
    HAS_BLST = False

@pytest.mark.skipif(not HAS_BLST, reason="Skipping MSM test: blst bindings not installed")
def test_ring_proof():
    file_path = os.path.join(HERE, "ark-vrf/bandersnatch_ed_sha512_ell2_ring.json")
    with open(file_path, 'r') as f:
        data = json.load(f)
    for index in range(len(data)-6):
        if index < 0 or index >= len(data):
            raise IndexError("Index out of range")
        item = data[index]
        s_k =item['sk']
        alpha = item['alpha']
        ad = item['ad']
        B_keys=item['ring_pks']
        # to get kzg coverage
        ring_root = RVRF.construct_ring_root(B_keys, True)
        p_k = RVRF.get_public_key(s_k)
        ring_vrf_proof = RVRF.ring_vrf_proof(alpha, ad,s_k,p_k,B_keys, True)
        assert p_k.hex()==item['pk'], "Invalid Public Key"
        assert ring_root.hex()==item['ring_pks_com'], "Invalid Ring Root"
        assert ring_vrf_proof.hex()==item['gamma']+item['proof_pk_com']+item['proof_r']+ item['proof_ok']+item['proof_s']+ item['proof_sb']+item['ring_proof'], "Unexpected Proof"
        assert RVRF.ring_vrf_proof_verify(ad,ring_root,ring_vrf_proof, alpha), "Verification Failed"
        print(f"✅ Testcase {index + 1} of {os.path.basename(file_path)}")