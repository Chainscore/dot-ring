import json
import os
import pytest
from dot_ring.curve.specs.bandersnatch import Bandersnatch
from dot_ring.curve.specs.baby_jubjub import BabyJubJub
from dot_ring.curve.specs.bandersnatch_sw import Bandersnatch_SW
from dot_ring.curve.specs.ed25519 import Ed25519_NU
from dot_ring.curve.specs.jubjub import JubJub
from dot_ring.curve.specs.p256 import P256_NU
from dot_ring.vrf.pedersen.pedersen import PedersenVRF

HERE = os.path.dirname(__file__)

TEST_CASES = [
    (Bandersnatch, "bandersnatch_ed_sha512_ell2_pedersen", "ark-vrf"),
    (BabyJubJub, "babyjubjub_sha512_tai_pedersen", "ark-vrf"),
    (Bandersnatch_SW, "bandersnatch_sw_sha512_tai_pedersen", "ark-vrf"),
    (Ed25519_NU, "ed25519_sha512_tai_pedersen.json", "ark-vrf"),
    (JubJub, "jubjub_sha512_tai_pedersen.json", "ark-vrf"),
    (P256_NU, "secp256r1_sha256_tai_pedersen", "ark-vrf"),
]

@pytest.mark.parametrize("curve_variant, file_prefix, subdir", TEST_CASES)
def test_pedersen_ietf(curve_variant, file_prefix, subdir):
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
                
                # Public Key check
                pk_bytes = PedersenVRF[curve_variant].get_public_key(secret_scalar)

                # Input Point check
                input_point = curve_variant.point.encode_to_curve(alpha)
                if 'h' in vector:
                    assert input_point.point_to_string().hex() == vector['h']
                
                proof = PedersenVRF[curve_variant].prove(alpha, secret_scalar, additional_data)
                proof_bytes = proof.to_bytes()
                proof_rt = PedersenVRF[curve_variant].from_bytes(proof_bytes)
                
                assert pk_bytes.hex() == vector['pk'], "Invalid Public Key"
                assert proof.output_point.point_to_string().hex() == vector["gamma"]
                assert proof.blinded_pk.point_to_string().hex() == vector["proof_pk_com"]
                assert proof.result_point.point_to_string().hex() == vector["proof_r"]
                assert proof.ok.point_to_string().hex() == vector["proof_ok"]
                assert proof.s.to_bytes((curve_variant.curve.PRIME_FIELD.bit_length() + 7) // 8, curve_variant.curve.ENDIAN) == bytes.fromhex(vector["proof_s"])
                assert proof.sb.to_bytes((curve_variant.curve.PRIME_FIELD.bit_length() + 7) // 8, curve_variant.curve.ENDIAN) == bytes.fromhex(vector["proof_sb"])
                assert PedersenVRF[curve_variant].ecvrf_proof_to_hash(proof.output_point.point_to_string()).hex() == vector["beta"]
                    
                if 'beta' in vector:
                    assert PedersenVRF[curve_variant].ecvrf_proof_to_hash(proof.output_point.point_to_string()).hex() == vector["beta"]

                assert proof.verify(alpha, additional_data)
                assert proof_rt.to_bytes() == proof_bytes
                assert proof_rt.verify(alpha, additional_data)
                
    if not found:
        pytest.skip(f"No vector files found for prefix {file_prefix} in {subdir}")
