import json
import os
import pytest
HERE = os.path.dirname(__file__)

from dot_ring.curve.specs.bandersnatch import (
    Bandersnatch_TE_Curve,
    BandersnatchPoint,
)
from dot_ring.vrf.ietf.ietf import IETF_VRF

# @pytest.mark.skipif("RUNALL" not in os.environ, reason="takes too long")
def test_prove_bandersnatch_ed_sha512_ell2_ietf():
    # Get the directory of the current test file
    # Construct the relative path to the data folder
    data_dir = os.path.join(HERE, "ark-vrf")
    limit = 10000
    for i, file in enumerate(os.listdir(data_dir)):
        print(file)
        if i >= limit:
            break
        if not file.startswith("bandersnatch_ed_sha512_ell2_ietf"):
            continue
        with open(os.path.join(data_dir, file), "r") as f:
            data = json.loads(f.read())
            for i, vector in enumerate(data):

                secret_scalar = vector["sk"]
                vrf = IETF_VRF(Bandersnatch_TE_Curve, BandersnatchPoint)
                proof = vrf.prove(vector["alpha"],secret_scalar,vector["ad"])
                gamma,c, s=  proof[:32].hex(), proof[32:64].hex(), proof[-32:].hex()
                assert gamma == vector["gamma"]
                assert c == vector["proof_c"]
                assert s == vector["proof_s"]
                assert vrf.ecvrf_proof_to_hash(proof).hex() == vector["beta"]
                print(f"✅ Testcase {i + 1} of {file}")


# @pytest.mark.skipif("RUNALL" not in os.environ, reason="takes too long")
def test_verify_bandersnatch_ed_sha512_ell2_ietf():
    # Get the directory of the current test file
    # Construct the relative path to the data folder
    data_dir = os.path.join(HERE,"ark-vrf")
    limit = 10000
    for i, file in enumerate(os.listdir(data_dir)):
        print(file)
        if i >= limit:
            break
        if not file.startswith("bandersnatch_ed_sha512_ell2_ietf"):
            continue
        with open(os.path.join(data_dir, file), "r") as f:
            data = json.loads(f.read())
            for i, vector in enumerate(data):

                secret_scalar = vector['sk']
                vrf = IETF_VRF(Bandersnatch_TE_Curve, BandersnatchPoint)
                proof = vrf.prove(vector["alpha"],secret_scalar,vector["ad"])
                pub_key = BandersnatchPoint.string_to_point(vector["pk"])
                input_point = BandersnatchPoint.encode_to_curve(vector["alpha"], vector["salt"])
                assert vrf.verify(pub_key,input_point,vector["ad"],proof)
                print(f"✅ Testcase {i + 1} of {file}")