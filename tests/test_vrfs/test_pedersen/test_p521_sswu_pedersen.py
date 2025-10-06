import json
import os
import pytest
HERE = os.path.dirname(__file__)

from dot_ring.curve.specs.p521 import (
    P521_SW_Curve,
    P521Point,
)
from dot_ring.vrf.pedersen.pedersen import PedersenVRF

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
        if not file.startswith("p521_base_vectors"):
            continue
        with open(os.path.join(data_dir, file), "r") as f:
            data = json.loads(f.read())
            for i, vector in enumerate(data[:-1]):
                secret_scalar = vector["sk"]
                vrf = PedersenVRF(P521_SW_Curve, P521Point)
                print(vrf.get_public_key(vector['sk']).hex()==vector['pk'])
                input_point=P521Point.encode_to_curve(vector['alpha']).point_to_string()
                proof = vrf.proof(vector["alpha"],secret_scalar,vector["ad"])
                verified=vrf.verify(P521Point.string_to_point(input_point), vector["ad"], proof)
                assert verified, "Proof Validation Failed"
                print(f"✅ Testcase {i + 1} of {file}")