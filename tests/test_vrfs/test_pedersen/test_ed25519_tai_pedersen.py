import json
import os

HERE = os.path.dirname(__file__)

from dot_ring.curve.specs.ed25519 import (
    nu_variant
)
from dot_ring.curve.e2c import E2C_Variant

point = nu_variant(E2C_Variant.TAI)
curve = point.curve

from dot_ring.vrf.pedersen.pedersen import PedersenVRF
# @pytest.mark.skipif("RUNALL" not in os.environ, reason="takes too long")
def test_bandersnatch_ed_sha512_ell2_ietf():
    # Get the directory of the current test file
    # Construct the relative path to the data folder
    data_dir = os.path.join(HERE, "../..", "ark-vrf/ietf")
    limit = 10000
    for i, file in enumerate(os.listdir(data_dir)):
        if i >= limit:
            break
        if not file.startswith("ed25519_sha512_tai_pedersen.json"):
            continue
        with open(os.path.join(data_dir, file), "r") as f:
            data = json.loads(f.read())
            for i, vector in enumerate(data):
                secret_scalar = vector['sk']
                vrf = PedersenVRF(curve, point)
                public_key = vrf.get_public_key(secret_scalar)
                proof, blinding = vrf.proof(vector["alpha"], secret_scalar, vector["ad"], True)
                assert blinding.hex() == vector['blinding']
                input_point = point.encode_to_curve(vector["alpha"], vector["salt"])
                assert vrf.verify(input_point, vector["ad"], proof)
                output_point, public_key_cp, R, Ok, S, Sb = (
                    proof[32 * 0:32 * 1], proof[32 * 1:32 * 2], proof[32 * 2:32 * 3], proof[32 * 3:32 * 4],
                    proof[32 * 4:32 * 5], proof[32 * 5:32 * 6])
                assert public_key.hex() == vector['pk'], "Invalid Public Key"
                assert output_point.hex() == vector["gamma"]
                assert public_key_cp.hex() == vector["proof_pk_com"]
                assert R.hex() == vector["proof_r"]
                assert Ok.hex() == vector["proof_ok"]
                assert S.hex() == vector["proof_s"]
                assert Sb.hex() == vector["proof_sb"]
                assert vrf.ecvrf_proof_to_hash(output_point).hex() == vector["beta"]
                assert vrf.verify(input_point, vector["ad"], proof)
                print(f"✅ Testcase {i + 1} of {file}")