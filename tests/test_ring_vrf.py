import time
import json
import os
import pytest
start_time=time.time()
from dot_ring.vrf.ring.ring_vrf import RingVrf as RVRF
HERE = os.path.dirname(__file__)

def test_ring_proof():
    file_path = os.path.join(HERE, "ark-vrf/bandersnatch_ed_sha512_ell2_ring.json")
    with open(file_path, 'r') as f:
        data = json.load(f)
    for index in range(len(data)):
        if index < 0 or index >= len(data):
            raise IndexError("Index out of range")
        item = data[index]
        blinding = item['blinding']
        s_k =item['sk']
        p_k = item['pk']
        alpha = item['alpha']
        ad = item['ad']
        B_keys_ring = bytes.fromhex(item['ring_pks'])
        B_keys=[B_keys_ring[32*i:32*(i+1)] for i in range(len(B_keys_ring)//32)]
        ring_root = RVRF.construct_ring_root(B_keys)
        ring_vrf_proof = RVRF.ring_vrf_proof(alpha, ad, blinding,s_k,p_k,B_keys)
        assert ring_root.hex()==item['ring_pks_com'], "Invalid Ring Root"
        assert ring_vrf_proof.hex()==item['gamma']+item['proof_pk_com']+item['proof_r']+ item['proof_ok']+item['proof_s']+ item['proof_sb']+item['ring_proof'], "Unexpected Proof"
        assert RVRF.ring_vrf_proof_verify(ad,ring_root,ring_vrf_proof, alpha), "Verification Failed"
        print(f"✅ Testcase {index + 1} of {os.path.basename(file_path)}")



