import json
import os
import pytest
HERE = os.path.dirname(__file__)

from dot_ring.curve.specs.p256 import (
    P256_SW_Curve,
    P256Point,
)
from dot_ring.vrf.ietf.ietf import IETF_VRF

# @pytest.mark.skipif("RUNALL" not in os.environ, reason="takes too long")
def test_prove_bandersnatch_ed_sha512_ell2_ietf():
    # Get the directory of the current test file
    # Construct the relative path to the data folder
    data_dir = os.path.join(HERE, 'vectors')
    data_dir = os.path.abspath(data_dir)  # normalize the path
    limit = 10000
    for i, file in enumerate(os.listdir(data_dir)):
        if i >= limit:
            break
        if not file.startswith("p256_base_vectors"):
            continue
        with open(os.path.join(data_dir, file), "r") as f:
            data = json.loads(f.read())
            for i, vector in enumerate(data):
                secret_scalar = vector["sk"]
                vrf = IETF_VRF(P256_SW_Curve, P256Point)
                input_point=P256Point.encode_to_curve(vector['alpha']).point_to_string()
                proof = vrf.proof(vector["alpha"],secret_scalar,vector["ad"])
                public_key=P256Point.string_to_point(vrf.get_public_key(vector['sk']))
                verified=vrf.verify(public_key, P256Point.string_to_point(input_point), vector["ad"], proof)
                assert verified, "Proof Validation Failed"
                print(f"✅ Testcase {i + 1} of {file}")