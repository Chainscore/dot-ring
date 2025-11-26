import time
import json
import os
import pytest
from dot_ring.vrf.ring.ring_vrf import RingVRF
from dot_ring.curve.specs.bandersnatch import Bandersnatch

HERE = os.path.dirname(__file__)

def test_ring_proof():
    file_path = os.path.join(HERE, "../vectors", "ark-vrf/bandersnatch_ed_sha512_ell2_ring.json")
    with open(file_path, 'r') as f:
        data = json.load(f)
    for index in range(len(data)):
        if index < 0 or index >= len(data):
            raise IndexError("Index out of range")
        item = data[index]
        s_k = bytes.fromhex(item['sk'])
        alpha = bytes.fromhex(item['alpha'])
        ad = bytes.fromhex(item['ad'])
        keys = RingVRF[Bandersnatch].parse_keys(bytes.fromhex(item['ring_pks']))
        
        start_time = time.time()
        ring_root = RingVRF[Bandersnatch].construct_ring_root(keys)
        ring_time = time.time()
        print(f"\nTime taken for Ring Root Construction: \t\t {ring_time - start_time} seconds")
        
        p_k = RingVRF[Bandersnatch].get_public_key(s_k)
        ring_vrf_proof = RingVRF[Bandersnatch].proof(alpha, ad, s_k, p_k, keys)
        proof_bytes = ring_vrf_proof.to_bytes()
        proof_rt = RingVRF[Bandersnatch].from_bytes(proof_bytes)
        
        end_time = time.time()
        print(f"Time taken for Ring VRF Proof Generation: \t {end_time - ring_time} seconds")
        
        assert p_k.hex() == item['pk'], "Invalid Public Key"
        assert ring_root.to_bytes().hex() == item['ring_pks_com'], "Invalid Ring Root"
        assert ring_vrf_proof.to_bytes().hex() == item['gamma'] + item['proof_pk_com'] + item['proof_r'] + item['proof_ok'] + item['proof_s'] + item['proof_sb'] + item['ring_proof'], "Unexpected Proof"
        start = time.time()
        assert ring_vrf_proof.verify(alpha, ad, ring_root), "Verification Failed"
        print("Time taken for Ring VRF Proof Verification: \t ", time.time() - start, " seconds")
        assert proof_rt.to_bytes() == proof_bytes
        assert proof_rt.verify(alpha, ad, ring_root)
        
        print(f"✅ Testcase {index + 1} of {os.path.basename(file_path)}")

