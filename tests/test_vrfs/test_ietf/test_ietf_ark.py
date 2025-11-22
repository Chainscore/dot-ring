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
from dot_ring.vrf.ietf.ietf import IETF_VRF

HERE = os.path.dirname(__file__)

def get_static(curve, point):
    return lambda: (curve, point)

def get_ed25519_tai():
    point = ed25519_nu_variant(E2C_Variant.TAI)
    return point.curve, point

def get_p256_tai():
    point = p256_nu_variant(E2C_Variant.TAI)
    return point.curve, point

# (curve_factory, file_prefix, subdir, gamma_len)
TEST_CASES = [
    (get_static(Bandersnatch_TE_Curve, BandersnatchPoint), "bandersnatch_ed_sha512_ell2_ietf", "ark-vrf", 32),
    (get_static(BabyJubJub_TE_Curve, BabyJubJubPoint), "babyjubjub_sha512_tai_ietf", "ark-vrf/ietf", 32),
    (get_static(Bandersnatch_SW_SW_Curve, Bandersnatch_SW_Point), "bandersnatch_sw_sha512_tai_ietf", "ark-vrf/ietf", 33),
    (get_ed25519_tai, "ed25519_sha512_tai_ietf.json", "ark-vrf/ietf", 32),
    (get_static(JubJub_TE_Curve, JubJubPoint), "jubjub_sha_512_tai_ietf", "ark-vrf/ietf", 32),
    (get_p256_tai, "secp256r1_sha256_tai_ietf.json", "ark-vrf/ietf", 33),
]

@pytest.mark.parametrize("curve_factory, file_prefix, subdir, gamma_len", TEST_CASES)
def test_ietf_ark(curve_factory, file_prefix, subdir, gamma_len):
    curve, point_class = curve_factory()
    
    data_dir = os.path.join(HERE, "../..", subdir)
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
                vrf = IETF_VRF(curve, point_class)
                
                # Public Key check
                pk_bytes = vrf.get_public_key(secret_scalar)
                public_key = point_class.string_to_point(pk_bytes)
                assert public_key.point_to_string().hex() == vector['pk']

                # Input Point check
                input_point = point_class.encode_to_curve(vector['alpha'])
                if 'h' in vector:
                    assert input_point.point_to_string().hex() == vector['h']
                
                proof = vrf.proof(vector["alpha"], secret_scalar, vector["ad"])
                
                # Proof components check
                gamma = proof[:gamma_len]
                proof_c = proof[gamma_len:-32]
                proof_s = proof[-32:]
                
                assert gamma.hex() == vector['gamma']
                assert proof_c.hex() == vector['proof_c']
                assert proof_s.hex() == vector['proof_s']
                
                if 'beta' in vector:
                     assert vrf.ecvrf_proof_to_hash(proof).hex() == vector["beta"]

                assert vrf.verify(public_key, input_point, vector["ad"], proof)
                
    if not found:
        pytest.skip(f"No vector files found for prefix {file_prefix} in {subdir}")
