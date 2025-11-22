import json
import os
import pytest
from dot_ring.curve.specs.curve25519 import Curve25519_MG_Curve, Curve25519Point
from dot_ring.curve.specs.p256 import P256_SW_Curve, P256Point
from dot_ring.curve.specs.curve448 import Curve448Point, Curve448_MG_Curve
from dot_ring.curve.specs.ed25519 import Ed25519_TE_Curve, Ed25519Point
from dot_ring.curve.specs.ed448 import Ed448_TE_Curve, Ed448Point
from dot_ring.curve.specs.p384 import P384_SW_Curve, P384Point
from dot_ring.curve.specs.p521 import P521_SW_Curve, P521Point
from dot_ring.curve.specs.secp256k1 import Secp256k1_SW_Curve, Secp256k1Point
from dot_ring.vrf.pedersen.pedersen import PedersenVRF

HERE = os.path.dirname(__file__)

TEST_CASES = [
    (Curve25519_MG_Curve, Curve25519Point, "curve25516_base_vectors", None),
    (P256_SW_Curve, P256Point, "p256_base_vectors", None),
    (Curve448_MG_Curve, Curve448Point, "curve448_base_vectors", None),
    (Ed25519_TE_Curve, Ed25519Point, "ed25519_base_vectors", None),
    (Ed448_TE_Curve, Ed448Point, "ed448_base_vectors", None),
    (P384_SW_Curve, P384Point, "p384_base_vectors", None),
    (P521_SW_Curve, P521Point, "p521_base_vectors", -1),
    (Secp256k1_SW_Curve, Secp256k1Point, "secp256k1_base_vectors", None),
]

@pytest.mark.parametrize("curve_class, point_class, file_prefix, slice_end", TEST_CASES)
def test_pedersen_base(curve_class, point_class, file_prefix, slice_end):
    data_dir = os.path.join(HERE, "./..", 'vectors')
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
            
            vectors = data[:slice_end] if slice_end is not None else data
            
            for j, vector in enumerate(vectors):
                secret_scalar = vector["sk"]
                vrf = PedersenVRF(curve_class, point_class)
                
                input_point = point_class.encode_to_curve(vector['alpha'])
                
                proof = vrf.proof(vector["alpha"], secret_scalar, vector["ad"])
                verified = vrf.verify(input_point, vector["ad"], proof)
                
                assert verified, f"Proof Verification Failed for {file} vector {j}"
    
    if not found:
        pytest.skip(f"No vector files found for prefix {file_prefix}")
