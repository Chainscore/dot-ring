import json
import os
import pytest

from dot_ring.curve.specs.bandersnatch import (
    Bandersnatch_TE_Curve,
    BandersnatchPoint,
)
from dot_ring.vrf.ietf.s_ietf import IETF_VRF

# @pytest.mark.skipif("RUNALL" not in os.environ, reason="takes too long")
def test_prove_bandersnatch_ed_sha512_ell2_ietf():
    data_dir = "/home/siva/PycharmProjects/dot_ring/tests/ark-vrf"
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
    data_dir = "/home/siva/PycharmProjects/tessera_JAM_VRF/tests/unit/vrf/data/ark-vrf"
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

# import json
# import os
#
# import pytest
#
# from dot_ring.curve.specs.bandersnatch import (
#     Bandersnatch_TE_Curve,
#     BandersnatchPoint,
# )
# from dot_ring.vrf.ietf.ietf import IETF_VRF
#
# # @pytest.mark.skipif("RUNALL" not in os.environ, reason="takes too long")
# def test_prove_bandersnatch_ed_sha512_ell2_ietf():
#     data_dir = "/home/siva/PycharmProjects/dot_ring/tests/ark-vrf"
#     limit = 10000
#     for i, file in enumerate(os.listdir(data_dir)):
#         print(file)
#         if i >= limit:
#             break
#         if not file.startswith("bandersnatch_ed_sha512_ell2_ietf"):
#             continue
#         with open(os.path.join(data_dir, file), "r") as f:
#             data = json.loads(f.read())
#             for i, vector in enumerate(data):
#                 secret_scalar = (
#                     int.from_bytes(bytes.fromhex(vector["sk"]), "little")
#                     % Bandersnatch_TE_Curve.ORDER
#                 )
#                 vrf = IETF_VRF(Bandersnatch_TE_Curve, BandersnatchPoint)
#                 output_point, proof = vrf.prove(
#                     bytes.fromhex(vector["alpha"]),
#                     secret_scalar,
#                     bytes.fromhex(vector["ad"]),
#                 )
#                 gamma = output_point.point_to_string().hex()
#                 assert gamma == vector["gamma"]
#                 assert proof[0] == int.from_bytes(
#                     bytes.fromhex(vector["proof_c"]), "little"
#                 )
#                 assert proof[1] == int.from_bytes(
#                     bytes.fromhex(vector["proof_s"]), "little"
#                 )
#                 assert vrf.proof_to_hash(output_point).hex() == vector["beta"]
#
#                 print(f"✅ Testcase {i + 1} of {file}")
#
#
# # @pytest.mark.skipif("RUNALL" not in os.environ, reason="takes too long")
# def test_verify_bandersnatch_ed_sha512_ell2_ietf():
#     data_dir = "/home/siva/PycharmProjects/tessera_JAM_VRF/tests/unit/vrf/data/ark-vrf"
#     limit = 10000
#     for i, file in enumerate(os.listdir(data_dir)):
#         print(file)
#         if i >= limit:
#             break
#         if not file.startswith("bandersnatch_ed_sha512_ell2_ietf"):
#             continue
#         with open(os.path.join(data_dir, file), "r") as f:
#             data = json.loads(f.read())
#             for i, vector in enumerate(data):
#                 secret_scalar = (
#                     int.from_bytes(bytes.fromhex(vector["sk"]), "little")
#                     % Bandersnatch_TE_Curve.ORDER
#                 )
#
#                 vrf = IETF_VRF(Bandersnatch_TE_Curve, BandersnatchPoint)
#                 output_point, proof = vrf.prove(
#                     bytes.fromhex(vector["alpha"]),
#                     secret_scalar,
#                     bytes.fromhex(vector["ad"]),
#                 )
#
#                 pub_key = BandersnatchPoint.string_to_point(vector["pk"])
#                 input_point = BandersnatchPoint.encode_to_curve(
#                     bytes.fromhex(vector["alpha"]), bytes.fromhex(vector["salt"])
#                 )
#
#                 assert vrf.verify(
#                     pub_key,
#                     input_point,
#                     bytes.fromhex(vector["ad"]),
#                     output_point,
#                     proof,
#                 )
#                 print(f"✅ Testcase {i + 1} of {file}")