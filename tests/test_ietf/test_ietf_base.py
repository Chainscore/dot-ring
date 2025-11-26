import json
import os
import pytest
from dot_ring.curve.specs.curve25519 import Curve25519_RO
from dot_ring.curve.specs.p256 import P256_RO
from dot_ring.curve.specs.curve448 import Curve448_RO
from dot_ring.curve.specs.ed25519 import Ed25519_RO
from dot_ring.curve.specs.ed448 import Ed448_RO
from dot_ring.curve.specs.p384 import P384_RO
from dot_ring.curve.specs.p521 import P521_RO
from dot_ring.curve.specs.secp256k1 import Secp256k1_RO
from dot_ring.vrf.ietf.ietf import IETF_VRF

HERE = os.path.dirname(__file__)

TEST_CASES = [
    (Curve25519_RO, "curve25516_base_vectors"),
    (P256_RO, "p256_base_vectors"),
    (Curve448_RO, "curve448_base_vectors"),
    (Ed25519_RO, "ed25519_base_vectors"),
    (Ed448_RO, "ed448_base_vectors"),
    (P384_RO, "p384_base_vectors"),
    (P521_RO, "p521_base_vectors"),
    (Secp256k1_RO, "secp256k1_base_vectors"),
]

@pytest.mark.parametrize("curve_variant, file_prefix", TEST_CASES)
def test_ietf_base(curve_variant, file_prefix):
    data_dir = os.path.join(HERE, "../", 'vectors/base')
    data_dir = os.path.abspath(data_dir)
    limit = 10000
    
    found = False
    for i, file in enumerate(os.listdir(data_dir)):
        if i >= limit:
            break
        if not file.startswith(file_prefix):
            continue
        
        found = True
        with open(os.path.join(data_dir, file), "r") as f:
            data = json.loads(f.read())
            
            for j, vector in enumerate(data):
                secret_scalar = bytes.fromhex(vector["sk"])
                alpha = bytes.fromhex(vector["alpha"])
                additional_data = bytes.fromhex(vector["ad"])
                
                # Public Key
                pk_bytes = IETF_VRF[curve_variant].get_public_key(secret_scalar)
                
                proof = IETF_VRF[curve_variant].proof(alpha, secret_scalar, additional_data)
                proof_bytes = proof.to_bytes()
                proof_rt = IETF_VRF[curve_variant].from_bytes(proof_bytes)
                
                # Verify
                verified = proof.verify(pk_bytes, alpha, additional_data)
                assert verified, f"Proof Verification Failed for {file} vector {j}"
                
                assert proof_rt.to_bytes() == proof_bytes
                assert proof_rt.verify(pk_bytes, alpha, additional_data)
    
    if not found:
        pytest.skip(f"No vector files found for prefix {file_prefix}")
