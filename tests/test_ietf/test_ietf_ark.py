import json
import os
import pytest
from dot_ring.curve.specs.bandersnatch import Bandersnatch
from dot_ring.curve.specs.baby_jubjub import BabyJubJub
from dot_ring.curve.specs.bandersnatch_sw import Bandersnatch_SW
from dot_ring.curve.specs.ed25519 import Ed25519_NU
from dot_ring.curve.specs.jubjub import JubJub
from dot_ring.curve.specs.p256 import P256_NU
from dot_ring.vrf.ietf.ietf import IETF_VRF

HERE = os.path.dirname(__file__)

# (curve_variant, file_prefix, subdir, gamma_len)
TEST_CASES = [
    (Bandersnatch, "bandersnatch_ed_sha512_ell2_ietf", "ark-vrf", 32),
    (BabyJubJub, "babyjubjub_sha512_tai_ietf", "ark-vrf", 32),
    (Bandersnatch_SW, "bandersnatch_sw_sha512_tai_ietf", "ark-vrf", 33),
    (Ed25519_NU, "ed25519_sha512_tai_ietf.json", "ark-vrf", 32),
    (JubJub, "jubjub_sha_512_tai_ietf", "ark-vrf", 32),
    (P256_NU, "secp256r1_sha256_tai_ietf.json", "ark-vrf", 33),
    (P256_NU, "secp256r1_sha256_tai_ietf_rfc_9381.json", "ark-vrf", 33),
]

@pytest.mark.parametrize("curve_variant, file_prefix, subdir, gamma_len", TEST_CASES)
def test_ietf_ark(curve_variant, file_prefix, subdir, gamma_len):
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
                secret_scalar = bytes.fromhex(vector["sk"])
                alpha = bytes.fromhex(vector["alpha"])
                additional_data = bytes.fromhex(vector["ad"])
                salt = bytes.fromhex(vector.get("salt", ""))
                
                # Public Key check
                pk_bytes = IETF_VRF[curve_variant].get_public_key(secret_scalar)
                public_key = curve_variant.point.string_to_point(pk_bytes)
                assert public_key.point_to_string().hex() == vector['pk']

                # Input Point check
                input_point = curve_variant.point.encode_to_curve(alpha, salt)
                if 'h' in vector:
                    assert input_point.point_to_string().hex() == vector['h']
                
                proof = IETF_VRF[curve_variant].proof(alpha, secret_scalar, additional_data, salt)
                proof_bytes = proof.to_bytes()
                proof_rt = IETF_VRF[curve_variant].from_bytes(proof_bytes)
                
                # Proof components check
                gamma = proof_bytes[:gamma_len]
                proof_c = proof_bytes[gamma_len:-32]
                proof_s = proof_bytes[-32:]
                
                assert gamma.hex() == vector['gamma']
                
                # Compare c and s as integers to handle potential padding differences in vectors
                assert int(proof_c.hex(), 16) == int(vector['proof_c'], 16)
                assert int(proof_s.hex(), 16) == int(vector['proof_s'], 16)
                
                if 'beta' in vector:
                    assert IETF_VRF[curve_variant].ecvrf_proof_to_hash(proof_bytes).hex() == vector["beta"]

                assert proof.verify(pk_bytes, alpha, additional_data, salt)
                assert proof_rt.to_bytes() == proof_bytes
                assert proof_rt.verify(pk_bytes, alpha, additional_data, salt)
                
    if not found:
        pytest.skip(f"No vector files found for prefix {file_prefix} in {subdir}")
