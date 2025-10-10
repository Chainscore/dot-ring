import json
import os

HERE = os.path.dirname(__file__)

from dot_ring.curve.specs.p256 import (
   nu_variant
)
from dot_ring.curve.e2c import E2C_Variant
from dot_ring.vrf.ietf.ietf import IETF_VRF


point = nu_variant(E2C_Variant.TAI)
curve = point.curve


# @pytest.mark.skipif("RUNALL" not in os.environ, reason="takes too long")
def test_bandersnatch_ed_sha512_ell2_ietf():
    # Get the directory of the current test file
    # Construct the relative path to the data folder
    data_dir = os.path.join(HERE, "../..", "ark-vrf/ietf")

    limit = 10000
    for i, file in enumerate(os.listdir(data_dir)):
        if i >= limit:
            break
        if not file.startswith("secp256r1_sha256_tai_ietf.json"):
            continue
        with open(os.path.join(data_dir, file), "r"
                  ) as f:
            data = json.loads(f.read())
            for i, vector in enumerate(data):
                secret_scalar = vector["sk"]
                vrf = IETF_VRF(curve, point)
                public_key=point.string_to_point(vrf.get_public_key(vector['sk']))
                assert public_key.point_to_string().hex() == vector['pk']
                input_point = point.encode_to_curve(vector['alpha'])
                assert input_point.point_to_string().hex() == vector['h']
                proof = vrf.proof(vector["alpha"], secret_scalar, vector["ad"])
                gamma, proof_c, proof_s = proof[:33].hex(), proof[33:-32].hex(), proof[-32:].hex()
                assert gamma == vector['gamma']
                assert proof_c == vector['proof_c']
                assert proof_s == vector['proof_s']
                assert vrf.verify(public_key, input_point, vector["ad"], proof)
                print(f"✅ Testcase {i + 1} of {file}")