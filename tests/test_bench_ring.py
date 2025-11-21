import json
import os
import sys
from pathlib import Path

# Add tests directory to path to import utils
sys.path.insert(0, str(Path(__file__).parent))

from dot_ring.vrf.ring.ring_vrf import RingVrf as RVRF
from utils.profiler import Profiler

HERE = os.path.dirname(__file__)
RESULTS_DIR = os.path.join(HERE, "results")


def load_test_data():
    """Load test vectors from JSON file - returns only first test case"""
    file_path = os.path.join(HERE, "ark-vrf/bandersnatch_ed_sha512_ell2_ring.json")
    with open(file_path, 'r') as f:
        data = json.load(f)
    return [data[0]]  # Return only first test case


def test_bench_ring_prove():
    """Benchmark Ring VRF proof generation with profiling"""
    data = load_test_data()
    
    # Create results directory
    os.makedirs(RESULTS_DIR, exist_ok=True)
    
    for index in range(len(data)):
        item = data[index]
        s_k = item['sk']
        alpha = item['alpha']
        ad = item['ad']
        B_keys = item['ring_pks']
        
        # Store ring size
        ring_root = RVRF.construct_ring_root(B_keys)
        p_k = RVRF.get_public_key(s_k)
        
        # Benchmark proof generation with profiling
        with Profiler(f"ring_prove_sample_{index+1}", 
                     save_stats=True, 
                     print_stats=False,
                     sort_by='cumulative',
                     limit=25):
            ring_vrf_proof = RVRF.ring_vrf_proof(alpha, ad, s_k, p_k, B_keys)
        
        # Verify correctness
        assert p_k.hex() == item['pk'], "Invalid Public Key"
        assert ring_root.hex() == item['ring_pks_com'], "Invalid Ring Root"
        expected_proof = (item['gamma'] + item['proof_pk_com'] + item['proof_r'] + 
                         item['proof_ok'] + item['proof_s'] + item['proof_sb'] + 
                         item['ring_proof'])
        assert ring_vrf_proof.hex() == expected_proof, "Unexpected Proof"
    
    print(f"📊 Profile saved to: perf/results/")


def test_bench_ring_verify():
    """Benchmark Ring VRF proof generation with profiling"""
    data = load_test_data()
    
    # Create results directory
    os.makedirs(RESULTS_DIR, exist_ok=True)
    
    for index in range(len(data)):
        item = data[index]
        alpha = item['alpha']
        ad = item['ad']
        
        proof = (item['gamma'] + item['proof_pk_com'] + item['proof_r'] + 
                                item['proof_ok'] + item['proof_s'] + item['proof_sb'] + 
                                item['ring_proof'])
        
        # Benchmark proof generation with profiling
        with Profiler(f"ring_verify_sample_{index+1}", 
                     save_stats=True, 
                     print_stats=False,
                     sort_by='cumulative',
                     limit=25):
            assert RVRF.ring_vrf_proof_verify(ad, bytes.fromhex(item['ring_pks_com']), bytes.fromhex(proof), alpha), "Verification Failed"
        

    print(f"📊 Profile saved to: perf/results/")

