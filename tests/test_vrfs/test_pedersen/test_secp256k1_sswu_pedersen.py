import json
import os
import pytest
from dot_ring.curve.specs.secp256k1 import Secp256k1_SW_Curve, Secp256k1Point
from dot_ring.vrf.pedersen.pedersen import PedersenVRF

HERE = os.path.dirname(__file__)
# @pytest.mark.skipif("RUNALL" not in os.environ, reason="takes too long")
def test_prove_bandersnatch_ed_sha512_ell2_ietf():
    # Get the directory of the current test file
    # Construct the relative path to the data folder
    data_dir = os.path.join(HERE, "./..", 'vectors')
    data_dir = os.path.abspath(data_dir)  # normalize the path
    limit = 10000
    for i, file in enumerate(os.listdir(data_dir)):
        if i >= limit:
            break
        if not file.startswith("secp256k1_base_vectors"):
            continue
        with open(os.path.join(data_dir, file), "r") as f:
            data = json.loads(f.read())
            for i, vector in enumerate(data):
                secret_scalar = vector["sk"]
                vrf = PedersenVRF(Secp256k1_SW_Curve, Secp256k1Point)
                input_point=Secp256k1Point.encode_to_curve(vector['alpha']).point_to_string()
                proof = vrf.proof(vector["alpha"],secret_scalar,vector["ad"])
                verified=vrf.verify(Secp256k1Point.string_to_point(input_point), vector["ad"], proof)
                assert verified, "Proof Validation Failed"
                print(f"✅ Testcase {i + 1} of {file}")