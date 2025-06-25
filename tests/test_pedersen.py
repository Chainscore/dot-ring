import json
import os
import pytest

from dot_ring.curve.specs.bandersnatch import (
    Bandersnatch_TE_Curve,
    BandersnatchPoint,
)
from dot_ring.ring_proof.helpers import Helpers
from dot_ring.vrf.pedersen.s_pedersen import PedersenVRF


# @pytest.mark.skipif("RUNALL" not in os.environ, reason="takes too long")
def test_prove_bandersnatch_ed_sha512_ell2_pedersen():
    ...
    data_dir = "/home/siva/PycharmProjects/dot_ring/tests/ark-vrf"
    limit = 10000
    for i, file in enumerate(os.listdir(data_dir)):
        print(file)
        if i >= limit:
            break
        if not file.startswith("bandersnatch_ed_sha512_ell2_pedersen"):
            continue
        with open(os.path.join(data_dir, file), "r") as f:
            data = json.loads(f.read())
            for i, vector in enumerate(data):
                secret_scalar = vector["sk"]
                vrf = PedersenVRF(Bandersnatch_TE_Curve, BandersnatchPoint)
                blinding_factor = vector["blinding"]
                proof = vrf.prove(vector["alpha"], secret_scalar, vector["ad"], blinding_factor)
                output_point,public_key_cp, R, Ok, S, Sb = (proof[32*0:32*1],proof[32 * 1:32 * 2],proof[32 * 2:32 * 3],proof[32 * 3:32 * 4],proof[32 * 4:32 * 5],proof[32 * 5:32 * 6])
                assert output_point.hex()== vector["gamma"]
                assert public_key_cp.hex() == vector["proof_pk_com"]
                assert R.hex() == vector["proof_r"]
                assert Ok.hex() == vector["proof_ok"]
                assert S.hex() == vector["proof_s"]
                assert Sb.hex() == vector["proof_sb"]
                assert vrf.ecvrf_proof_to_hash(output_point).hex() == vector["beta"]
                print(f"✅ Testcase {i + 1} of {file}")


# @pytest.mark.skipif("RUNALL" not in os.environ, reason="takes too long")
def test_verify_bandersnatch_ed_sha512_ell2_ietf():
    ...
    data_dir = "/home/siva/PycharmProjects/dot_ring/tests/ark-vrf"
    limit = 10000
    for i, file in enumerate(os.listdir(data_dir)):
        print(file)
        if i >= limit:
            break
        if not file.startswith("bandersnatch_ed_sha512_ell2_pedersen"):
            continue
        with open(os.path.join(data_dir, file), "r") as f:
            data = json.loads(f.read())
            for i, vector in enumerate(data):
                secret_scalar =vector["sk"]
                vrf = PedersenVRF(Bandersnatch_TE_Curve, BandersnatchPoint)
                blinding_factor = vector["blinding"]
                proof = vrf.prove(vector["alpha"],secret_scalar,vector["ad"],blinding_factor)
                input_point = BandersnatchPoint.encode_to_curve(vector["alpha"],vector["salt"])
                assert vrf.verify(input_point, vector["ad"],proof)
                print(f"✅ Testcase {i + 1} of {file}")



# @pytest.mark.skipif("RUNALL" not in os.environ, reason="takes too long")
# def test_prove_bandersnatch_ed_sha512_ell2_pedersen():
#     ...
#     data_dir = "/home/siva/PycharmProjects/dot_ring/tests/ark-vrf"
#     limit = 10000
#     for i, file in enumerate(os.listdir(data_dir)):
#         print(file)
#         if i >= limit:
#             break
#         if not file.startswith("bandersnatch_ed_sha512_ell2_pedersen"):
#             continue
#         with open(os.path.join(data_dir, file), "r") as f:
#             data = json.loads(f.read())
#             for i, vector in enumerate(data):
#                 secret_scalar = (
#                     int.from_bytes(bytes.fromhex(vector["sk"]), "little")
#                     % Bandersnatch_TE_Curve.ORDER
#                 )
#                 vrf = PedersenVRF(Bandersnatch_TE_Curve, BandersnatchPoint)
#                 blinding_factor = (
#                     int.from_bytes(bytes.fromhex(vector["blinding"]), "little")
#                     % Bandersnatch_TE_Curve.ORDER
#                 )
#                 output_point, proof = vrf.prove(
#                     bytes.fromhex(vector["alpha"]),
#                     secret_scalar,
#                     bytes.fromhex(vector["ad"]),
#                     blinding_factor,
#                 )
#                 assert output_point.point_to_string().hex() == vector["gamma"]
#                 assert proof[0].point_to_string().hex() == vector["proof_pk_com"]
#                 assert proof[1].point_to_string().hex() == vector["proof_r"]
#                 assert proof[2].point_to_string().hex() == vector["proof_ok"]
#                 assert proof[3] == int.from_bytes(
#                     bytes.fromhex(vector["proof_s"]), "little"
#                 )
#                 assert proof[4] == int.from_bytes(
#                     bytes.fromhex(vector["proof_sb"]), "little"
#                 )
#                 assert vrf.proof_to_hash(output_point).hex() == vector["beta"]
#                 print(f"✅ Testcase {i + 1} of {file}")
#
#
# # @pytest.mark.skipif("RUNALL" not in os.environ, reason="takes too long")
# def test_verify_bandersnatch_ed_sha512_ell2_ietf():
#     ...
#     data_dir = "/home/siva/PycharmProjects/dot_ring/tests/ark-vrf"
#     limit = 10000
#     for i, file in enumerate(os.listdir(data_dir)):
#         print(file)
#         if i >= limit:
#             break
#         if not file.startswith("bandersnatch_ed_sha512_ell2_pedersen"):
#             continue
#         with open(os.path.join(data_dir, file), "r") as f:
#             data = json.loads(f.read())
#             for i, vector in enumerate(data):
#                 secret_scalar = (
#                     int.from_bytes(bytes.fromhex(vector["sk"]), "little")
#                     % Bandersnatch_TE_Curve.ORDER
#                 )
#
#                 vrf = PedersenVRF(Bandersnatch_TE_Curve, BandersnatchPoint)
#
#                 blinding_factor = (
#                     int.from_bytes(bytes.fromhex(vector["blinding"]), "little")
#                     % Bandersnatch_TE_Curve.ORDER
#                 )
#
#                 output_point, proof = vrf.prove(
#                     bytes.fromhex(vector["alpha"]),
#                     secret_scalar,
#                     bytes.fromhex(vector["ad"]),
#                     blinding_factor,
#                 )
#
#                 input_point = BandersnatchPoint.encode_to_curve(
#                     bytes.fromhex(vector["alpha"]), bytes.fromhex(vector["salt"])
#                 )
#
#                 assert vrf.verify(
#                     input_point, bytes.fromhex(vector["ad"]), output_point, proof
#                 )
#                 print(f"✅ Testcase {i + 1} of {file}")