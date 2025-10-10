import json
import os
import pytest
HERE = os.path.dirname(__file__)
from dot_ring.curve.specs.p256 import (
   nu_variant
)
from dot_ring.curve.e2c import E2C_Variant
from dot_ring.vrf.pedersen.pedersen import PedersenVRF

# @pytest.mark.skipif("RUNALL" not in os.environ, reason="takes too long")
def test_prove_bandersnatch_ed_sha512_ell2_pedersen():
    data_dir = os.path.join(HERE, "../..", "ark-vrf/ietf")
    limit = 10000
    for i, file in enumerate(os.listdir(data_dir)):
        if i >= limit:
            break
        if not file.startswith("secp256r1_sha256_tai_pedersen"):
            continue
        with open(os.path.join(data_dir, file), "r") as f:
            point = nu_variant(E2C_Variant.TAI)
            curve = point.curve
            data = json.loads(f.read())
            for i, vector in enumerate(data):
                secret_scalar = vector["sk"]
                vrf = PedersenVRF(curve, point)
                public_key=vrf.get_public_key(secret_scalar)
                proof = vrf.proof(vector["alpha"], secret_scalar, vector["ad"])
                output_point,public_key_cp, R, Ok, S, Sb = (proof[33*0:33*1],proof[33 * 1:33 * 2],proof[33 * 2:33 * 3],proof[33 * 3:33 * 4],proof[33 * 4:-32],proof[-32:])
                assert public_key.hex()== vector['pk'], "Invalid Public Key"
                assert output_point.hex()== vector["gamma"]
                assert public_key_cp.hex() == vector["proof_pk_com"]
                assert R.hex() == vector["proof_r"]
                assert Ok.hex() == vector["proof_ok"]
                assert S.hex() == vector["proof_s"]
                assert Sb.hex() == vector["proof_sb"]
                assert vrf.ecvrf_proof_to_hash(output_point).hex() == vector["beta"]
                input_point = point.encode_to_curve(vector["alpha"],vector["salt"])
                assert vrf.verify(input_point, vector["ad"],proof)
                print(f"✅ Testcase {i + 1} of {file}")