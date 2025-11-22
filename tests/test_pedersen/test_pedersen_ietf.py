import json
import os
import pytest
from dot_ring.curve.specs.bandersnatch import Bandersnatch_TE_Curve, BandersnatchPoint
from dot_ring.curve.specs.baby_jubjub import BabyJubJub_TE_Curve, BabyJubJubPoint
from dot_ring.curve.specs.bandersnatch_sw import Bandersnatch_SW_SW_Curve, Bandersnatch_SW_Point
from dot_ring.curve.specs.ed25519 import nu_variant as ed25519_nu_variant
from dot_ring.curve.specs.jubjub import JubJub_TE_Curve, JubJubPoint
from dot_ring.curve.specs.p256 import nu_variant as p256_nu_variant
from dot_ring.curve.e2c import E2C_Variant
from dot_ring.vrf.pedersen.pedersen import PedersenVRF

HERE = os.path.dirname(__file__)

def get_static(curve, point):
    return lambda: (curve, point)

def get_ed25519_tai():
    point = ed25519_nu_variant(E2C_Variant.TAI)
    return point.curve, point

def get_p256_tai():
    point = p256_nu_variant(E2C_Variant.TAI)
    return point.curve, point

TEST_CASES = [
    (get_static(Bandersnatch_TE_Curve, BandersnatchPoint), "bandersnatch_ed_sha512_ell2_pedersen", "ark-vrf", 32, False),
    (get_static(BabyJubJub_TE_Curve, BabyJubJubPoint), "babyjubjub_sha512_tai_pedersen", "ark-vrf", 32, False),
    (get_static(Bandersnatch_SW_SW_Curve, Bandersnatch_SW_Point), "bandersnatch_sw_sha512_tai_pedersen", "ark-vrf", 33, False),
    (get_ed25519_tai, "ed25519_sha512_tai_pedersen.json", "ark-vrf", 32, True),
    (get_static(JubJub_TE_Curve, JubJubPoint), "jubjub_sha512_tai_pedersen.json", "ark-vrf", 32, True),
    (get_p256_tai, "secp256r1_sha256_tai_pedersen", "ark-vrf", 33, False),
]

@pytest.mark.parametrize("curve_factory, file_prefix, subdir, point_size, check_blinding", TEST_CASES)
def test_pedersen_ietf(curve_factory, file_prefix, subdir, point_size, check_blinding):
    curve, point_class = curve_factory()
    
    data_dir = os.path.join(HERE, "../vectors", subdir)
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
                secret_scalar = vector["sk"]
                vrf = PedersenVRF(curve, point_class)
                
                public_key = vrf.get_public_key(secret_scalar)
                
                if check_blinding:
                    proof, blinding = vrf.proof(vector["alpha"], secret_scalar, vector["ad"], True, vector.get("salt", ""))
                    assert blinding.hex() == vector['blinding']
                else:
                    proof = vrf.proof(vector["alpha"], secret_scalar, vector["ad"], False, vector.get("salt", ""))
                
                # Slicing logic
                # output_point, public_key_cp, R, Ok are point_size bytes
                # S is variable (but usually 32), Sb is 32 bytes
                
                p_sz = point_size
                output_point = proof[0 : p_sz]
                public_key_cp = proof[p_sz : 2*p_sz]
                R = proof[2*p_sz : 3*p_sz]
                Ok = proof[3*p_sz : 4*p_sz]
                S = proof[4*p_sz : -32]
                Sb = proof[-32:]
                
                assert public_key.hex() == vector['pk'], "Invalid Public Key"
                assert output_point.hex() == vector["gamma"]
                assert public_key_cp.hex() == vector["proof_pk_com"]
                assert R.hex() == vector["proof_r"]
                assert Ok.hex() == vector["proof_ok"]
                assert S.hex() == vector["proof_s"]
                assert Sb.hex() == vector["proof_sb"]
                assert vrf.ecvrf_proof_to_hash(output_point).hex() == vector["beta"]
                
                input_point = point_class.encode_to_curve(vector["alpha"], vector["salt"])
                assert vrf.verify(input_point, vector["ad"], proof)
                
    if not found:
        pytest.skip(f"No vector files found for prefix {file_prefix} in {subdir}")
