"""Quick run to test functionality, isolated to Bandersnatch. Running all tests on all curves is recommended."""
import json
import os
from dot_ring.vrf.pedersen.pedersen import PedersenVRF
from dot_ring.curve.specs.bandersnatch import Bandersnatch
from dot_ring.vrf.ietf.ietf import IETF_VRF
from dot_ring.vrf.ring.ring_vrf import RingVRF

HERE = os.path.dirname(__file__)


def test_ietf_ark_bandersnatch():
    data_dir = os.path.join(HERE, "vectors/ark-vrf/bandersnatch_ed_sha512_ell2_ietf.json")
    data_dir = os.path.abspath(data_dir)
    
    gamma_len = 32
    
    with open(data_dir, "r") as f:
        data = json.loads(f.read())
        for j, vector in enumerate(data):
            secret_scalar, alpha, additional_data = bytes.fromhex(vector["sk"]), bytes.fromhex(vector["alpha"]), bytes.fromhex(vector["ad"])
            
            # Public Key check
            pk_bytes = IETF_VRF[Bandersnatch].get_public_key(secret_scalar)
            public_key = Bandersnatch.point.string_to_point(pk_bytes)
            assert public_key.point_to_string().hex() == vector['pk']

            # Input Point check
            input_point = Bandersnatch.point.encode_to_curve(vector['alpha'])
            if 'h' in vector:
                assert input_point.point_to_string().hex() == vector['h']
            
            proof = IETF_VRF[Bandersnatch].proof(alpha, secret_scalar, additional_data)
            proof_bytes = proof.to_bytes()
            proof_rt = IETF_VRF[Bandersnatch].from_bytes(proof_bytes)
            
            # Proof components check
            gamma = proof_bytes[:gamma_len]
            proof_c = proof_bytes[gamma_len:-32]
            proof_s = proof_bytes[-32:]
            
            assert gamma.hex() == vector['gamma']
            assert proof_c.hex() == vector['proof_c']
            assert proof_s.hex() == vector['proof_s']
            
            if 'beta' in vector:
                assert IETF_VRF[Bandersnatch].ecvrf_proof_to_hash(proof_bytes).hex() == vector["beta"]

            assert proof.verify(pk_bytes, alpha, additional_data)
            assert proof_rt.to_bytes() == proof_bytes
            assert proof_rt.verify(pk_bytes, alpha, additional_data)
            
def test_pedersen_ark_bandersnatch():
    data_dir = os.path.join(HERE, "vectors/ark-vrf/bandersnatch_ed_sha512_ell2_pedersen.json")
    data_dir = os.path.abspath(data_dir)
    
    with open(data_dir, "r") as f:
        data = json.loads(f.read())
        for j, vector in enumerate(data):
            secret_scalar, alpha, additional_data = bytes.fromhex(vector["sk"]), bytes.fromhex(vector["alpha"]), bytes.fromhex(vector["ad"])
                
            # Public Key check
            pk_bytes = PedersenVRF[Bandersnatch].get_public_key(secret_scalar)

            # Input Point check
            input_point = Bandersnatch.point.encode_to_curve(alpha)
            if 'h' in vector:
                assert input_point.point_to_string().hex() == vector['h']
            
            proof = PedersenVRF[Bandersnatch].proof(
                alpha, 
                secret_scalar, 
                additional_data
            )
            proof_bytes = proof.to_bytes()
            proof_rt = PedersenVRF[Bandersnatch].from_bytes(proof_bytes)
            
            assert pk_bytes.hex() == vector['pk'], "Invalid Public Key"
            assert proof.output_point.point_to_string().hex() == vector["gamma"]
            assert proof.blinded_pk.point_to_string().hex() == vector["proof_pk_com"]
            assert proof.result_point.point_to_string().hex() == vector["proof_r"]
            assert proof.ok.point_to_string().hex() == vector["proof_ok"]
            assert proof.s.to_bytes((Bandersnatch.curve.PRIME_FIELD.bit_length() + 7) // 8, Bandersnatch.curve.ENDIAN) == bytes.fromhex(vector["proof_s"])
            assert proof.sb.to_bytes((Bandersnatch.curve.PRIME_FIELD.bit_length() + 7) // 8, Bandersnatch.curve.ENDIAN) == bytes.fromhex(vector["proof_sb"])
            assert PedersenVRF[Bandersnatch].ecvrf_proof_to_hash(proof.output_point.point_to_string()).hex() == vector["beta"]
                
            if 'beta' in vector:
                assert PedersenVRF[Bandersnatch].ecvrf_proof_to_hash(proof.output_point.point_to_string()).hex() == vector["beta"]

            assert proof.verify(alpha, additional_data)
            assert proof_rt.to_bytes() == proof_bytes
            assert proof_rt.verify(alpha, additional_data)
            
def test_ring_proof():
    file_path = os.path.join(HERE, "vectors/ark-vrf/bandersnatch_ed_sha512_ell2_ring.json")
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
        ring_root = RingVRF[Bandersnatch].construct_ring_root(keys)
        p_k = RingVRF[Bandersnatch].get_public_key(s_k)
        ring_vrf_proof = RingVRF[Bandersnatch].proof(alpha, ad, s_k, p_k, keys)
        proof_bytes = ring_vrf_proof.to_bytes()
        proof_rt = RingVRF[Bandersnatch].from_bytes(proof_bytes)
        
        assert p_k.hex()==item['pk'], "Invalid Public Key"
        assert ring_root.to_bytes().hex()==item['ring_pks_com'], "Invalid Ring Root"
        assert ring_vrf_proof.to_bytes().hex()==item['gamma']+item['proof_pk_com']+item['proof_r']+ item['proof_ok']+item['proof_s']+ item['proof_sb']+item['ring_proof'], "Unexpected Proof"
        
        assert ring_vrf_proof.verify(alpha, ad, ring_root), "Verification Failed"
        assert proof_rt.to_bytes() == proof_bytes
        assert proof_rt.verify(alpha, ad, ring_root)
        print(f"✅ Testcase {index + 1} of {os.path.basename(file_path)}")

