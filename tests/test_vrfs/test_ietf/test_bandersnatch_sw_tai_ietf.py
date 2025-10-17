import json
import os
import pytest
from dot_ring.ring_proof.helpers import Helpers
HERE = os.path.dirname(__file__)

from dot_ring.curve.specs.bandersnatch_sw import (
    Bandersnatch_SW_SW_Curve,
    Bandersnatch_SW_Point,
)
from dot_ring.vrf.ietf.ietf import IETF_VRF

# @pytest.mark.skipif("RUNALL" not in os.environ, reason="takes too long")
def test_prove_bandersnatch_ed_sha512_ell2_ietf():
    # Get the directory of the current test file
    # Construct the relative path to the data folder
    data_dir = os.path.join(HERE, "../..", "ark-vrf/ietf")
    data_dir = os.path.abspath(data_dir)  # normalize the path
    limit = 10000
    for i, file in enumerate(os.listdir(data_dir)):
        if i >= limit:
            break
        if not file.startswith("bandersnatch_sw_sha512_tai_ietf"):
            continue
        with open(os.path.join(data_dir, file), "r") as f:
            data = json.loads(f.read())
            for i, vector in enumerate(data):
                secret_scalar = vector["sk"]
                vrf = IETF_VRF(Bandersnatch_SW_SW_Curve, Bandersnatch_SW_Point)
                public_key = vrf.get_public_key(vector['sk']).hex()
                assert  public_key==vector['pk'], "Invalid PK"
                input_point = Bandersnatch_SW_Point.encode_to_curve(vector['alpha'])
                assert input_point.point_to_string().hex()==vector['h'], "Invalid Input Point"
                proof = vrf.proof(vector["alpha"], secret_scalar, vector["ad"])
                gamma, proof_c, proof_s = proof[:33].hex(), proof[33:-32].hex(), proof[-32:].hex()
                assert gamma == vector['gamma']
                assert proof_c == vector['proof_c']
                assert proof_s == vector['proof_s']
                assert vrf.verify(Bandersnatch_SW_Point.string_to_point(public_key), input_point, vector["ad"], proof)
                print(f"✅ Testcase {i + 1} of {file}")