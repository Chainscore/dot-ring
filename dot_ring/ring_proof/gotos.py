# mypy: ignore-errors
import time
from typing import List, Any
from dot_ring.ring_proof.curve.bandersnatch import TwistedEdwardCurve
# from dot_ring.types.base import ByteArray32
# from dot_ring.types.protocol.crypto import BandersnatchPublic
from dot_ring.ring_proof.columns.columns import PublicColumnBuilder as PC
from dot_ring.ring_proof.pcs.kzg import KZG
from dot_ring.ring_proof.pcs.load_powers import g1_points, g2_points
from dot_ring.fiat_shamir.phases import phase1_alphas
from dot_ring.fiat_shamir.transcript import Transcript
# from dot_ring.ring_proof.short_weierstrass.curve import ShortWeierstrassCurve as sw
from dot_ring.ring_proof.constants import Blinding_Base, S_PRIME, OMEGA_2048, SeedPoint
from dot_ring.ring_proof.columns.columns import WitnessColumnBuilder, PublicColumnBuilder
from dot_ring.ring_proof.constraints.constraints import RingConstraintBuilder
from dot_ring.ring_proof.helpers import Helpers as H, Helpers
from py_ecc.optimized_bls12_381 import normalize as nm
from dot_ring.ring_proof.constraints.aggregation import aggregate_constraints
from dot_ring.ring_proof.proof.quotient_poly import QuotientPoly
from dot_ring.ring_proof.proof.linearization_poly import LAggPoly
from dot_ring.ring_proof.proof.aggregation_poly import AggPoly
from dot_ring.ring_proof.verify import Verify
from dot_ring.ring_proof.constants import D_512 as D
from dot_ring.curves.specs.bandersnatch import BandersnatchCurve, BandersnatchPoint
Bandersnatch_TE_Curve = BandersnatchCurve()
from dot_ring.vrf.pedersen.pedersen import PedersenVRF


# from dot_ring.vrf.pedersen.pedersen import PedersenVRF

# def generate_bls_signature(secret_t,producer_key, keys: List[BandersnatchPublic]):
def generate_bls_signature(secret_t:bytes|str,producer_key:bytes|str, keys: List[Any], third_party_msm:bool)->bytes:
    """
    get the all the data needed and
    return the signature as an output
    """
    kzg = KZG.default(use_third_party_commit=third_party_msm)
    # signature = func() #make the call or logic u want
    # return signature
    if not isinstance(producer_key, bytes):
        producer_key_point = BandersnatchPoint.string_to_point(bytes.fromhex(producer_key))
    else:
        producer_key_point = BandersnatchPoint.string_to_point(producer_key)

    secret_t=Helpers.l_endian_2_int(secret_t)
    producer_key_pt= (producer_key_point.x, producer_key_point.y)
    keys_as_bs_points = []

    for key in keys:
        if isinstance(key, bytes):
            point = BandersnatchPoint.string_to_point(key)
        else:
            point = BandersnatchPoint.string_to_point(bytes(key))  # or take key[2:] by skipping '0x'
        keys_as_bs_points.append((point.x, point.y))

    ring_root = PC()  # ring_root builder
    fixed_cols = ring_root.build(keys_as_bs_points, kzg)
    ring_root_bs = bytearray.fromhex(H.bls_g1_compress(fixed_cols[0].commitment)).hex() + bytearray.fromhex(
        H.bls_g1_compress(fixed_cols[1].commitment)).hex() + bytearray.fromhex(
        H.bls_g1_compress(fixed_cols[2].commitment)).hex()
    s_v = fixed_cols[-1].evals
    producer_index= keys_as_bs_points.index(producer_key_pt)
    witness_obj = WitnessColumnBuilder(keys_as_bs_points, s_v, producer_index, secret_t)
    witness_res = witness_obj.build(kzg)
    witness_relation_res = witness_obj.result(Blinding_Base)
    Result_plus_Seed = witness_obj.result_p_seed(witness_relation_res)
    constraints = RingConstraintBuilder(Result_plus_Seed, fixed_cols[0].coeffs, fixed_cols[1].coeffs,
                                        fixed_cols[2].coeffs, witness_res[0].coeffs, witness_res[1].coeffs,
                                        witness_res[2].coeffs, witness_res[3].coeffs)

    constraint_dict = constraints.compute()
    fixed_col_commits = [H.to_int(nm(fixed_cols[0].commitment)), H.to_int(nm(fixed_cols[1].commitment)),
                         H.to_int(nm(fixed_cols[2].commitment))]

    ws = witness_res
    witness_commitments = [H.to_int(nm(ws[0].commitment)), H.to_int(nm(ws[-1].commitment)),
                           H.to_int(nm(ws[1].commitment)), H.to_int(nm(ws[2].commitment))]

    vk = {
        'g1': g1_points[0],
        'g2': H.altered_points(g2_points),
        'commitments': fixed_col_commits
    }
    t = Transcript(S_PRIME, b"Bandersnatch_SHA-512_ELL2")
    t, alpha = phase1_alphas(t, vk, witness_relation_res, witness_commitments)

    cd = constraint_dict
    c_polys = [cd[val] for val in cd]
    C_agg = aggregate_constraints(c_polys, alpha, OMEGA_2048, S_PRIME)
    qp = QuotientPoly(kzg)
    Q_p, C_q = qp.quotient_poly(C_agg)
    C_q_nm = nm(C_q)
    l_obj = LAggPoly(t, H.to_int(C_q_nm), fixed_cols, ws, alpha)
    current_t, zeta, rel_poly_evals, l_agg, zeta_omega, l_zw = l_obj.l_agg_poly()
    obj = AggPoly(current_t, zeta, fixed_cols, ws, Q_p, C_q, rel_poly_evals, l_agg, zeta_omega, l_zw, kzg)

    cf_vs, proof_ptr, proof_bs = obj.construct_proof()
    return bytes.fromhex(proof_bs) #bytess string

# def construct_ring_root(keys: List[BandersnatchPublic]):
def construct_ring_root(keys: List[Any], third_party_msm:bool)->bytes:
    """
    get the data needed and construct the rng root
    """
    kzg = KZG.default(use_third_party_commit=third_party_msm)
    # ring_root= func() make the call ore logic u want
    #return ring_root
    keys_as_bs_points = []
    for key in keys:
        point = BandersnatchPoint.string_to_point(bytes(key))  # or take key[2:] by skipping '0x'
        keys_as_bs_points.append((point.x, point.y))
    t = time.time()
    ring_root = PC()  # ring_root builder
    fixed_cols = ring_root.build(keys_as_bs_points, kzg)

    fxd_col_cs = bytes.fromhex(H.bls_g1_compress(fixed_cols[0].commitment))+ bytes.fromhex(
        H.bls_g1_compress(fixed_cols[1].commitment))+ bytes.fromhex(
        H.bls_g1_compress(fixed_cols[2].commitment))
    return fxd_col_cs


def verify_signature(message:bytes|str, ring_root:bytes|str, proof:bytes|str)->bool:
    """
    get the bls signature, other params if needed and verify it
    """
    # is_valid=func() # make the func call or logic u want
    # return is_valid
    if not isinstance(proof, bytes):
        proof=bytes.fromhex(proof)

    proof_ptr = [H.bls_g1_decompress(proof[:48]),
                 H.bls_g1_decompress(proof[48 * 1: 48 * 2]),
                 H.bls_g1_decompress(proof[48 * 2: 48 * 3]),
                 H.bls_g1_decompress(proof[48 * 3:48 * 4]),
                 H.to_scalar_int(proof[48 * 4 + (0 * 32): 48 * 4 + (1 * 32)]),
                 H.to_scalar_int(proof[48 * 4 + (1 * 32): 48 * 4 + (2 * 32)]),
                 H.to_scalar_int(proof[48 * 4 + (2 * 32): 48 * 4 + (3 * 32)]),
                 H.to_scalar_int(proof[48 * 4 + (3 * 32): 48 * 4 + (4 * 32)]),
                 H.to_scalar_int(proof[48 * 4 + (4 * 32): 48 * 4 + (5 * 32)]),
                 H.to_scalar_int(proof[48 * 4 + (5 * 32): 48 * 4 + (6 * 32)]),
                 H.to_scalar_int(proof[48 * 4 + (6 * 32): 48 * 4 + (7 * 32)]),
                 H.bls_g1_decompress(proof[48 * 4 + (7 * 32):(48 * 4) + (7 * 32) + 48]),
                 H.to_scalar_int(proof[(48 * 4) + (7 * 32) + 48: 48 * 4 + (7 * 32) + 48 + 32]),
                 H.bls_g1_decompress(proof[48 * 4 + (7 * 32) + 48 + 32:-48]),
                 H.bls_g1_decompress(proof[-48:])]

    if not isinstance(ring_root, bytes):
        ring_root=bytes.fromhex(ring_root)

    rltn_to_proove =BandersnatchPoint.string_to_point(message) #relation to proove
    rltn=(rltn_to_proove.x, rltn_to_proove.y)
    res_plus_seed= TwistedEdwardCurve.add(SeedPoint,rltn)
    C_px, C_py, C_s = H.bls_g1_decompress(ring_root[:48]), H.bls_g1_decompress(ring_root[48:-48]), H.bls_g1_decompress(
        ring_root[-48:])
    fixed_cols_cmts = [C_px, C_py, C_s]
    verifier_key = {
        'g1': g1_points[0],
        'g2': H.altered_points(g2_points),
        'commitments': [H.to_int(each) for each in H.bls_projective_2_affine(fixed_cols_cmts)]
    }
    valid = Verify(proof_ptr, verifier_key, fixed_cols_cmts, rltn, res_plus_seed, SeedPoint, D)
    return valid.is_signtaure_valid()


# def ring_vrf_proof(alpha, add, blinding_factor, producer_key, keys:List[BandersnatchPublic]):
def ring_vrf_proof(alpha:bytes|str, add:bytes|str, blinding_factor:bytes|str, secret_key:bytes|str, producer_key:bytes|str, keys:List[Any], third_party_msm:bool)->bytes:
    """get the args u want and generate the
    ring_vrf_proof (pedersen vrf proof + ring_proof ) \
    which of length 784 bytes"""
    kzg = KZG.default(use_third_party_commit=third_party_msm)

    if not isinstance(alpha, bytes):
        alpha=bytes.fromhex(alpha)

    if not isinstance(add, bytes):
        add= bytes.fromhex(add)
    if not isinstance(add, bytes):
        add = bytes.fromhex(add)
    if not isinstance(blinding_factor, bytes):
        blinding_factor = bytes.fromhex(blinding_factor)
    if not isinstance(add, bytes):
        secret_key = bytes.fromhex(secret_key)

    #pedersen_proof=get the pedersen proof
    vrf = PedersenVRF(Bandersnatch_TE_Curve, BandersnatchPoint)
    pedersen_proof = vrf.proof(alpha,secret_key,add,blinding_factor)
    #ring_proof= get the ring_signature
    ring_proof= generate_bls_signature(blinding_factor,producer_key, keys, third_party_msm)
    if not isinstance(ring_proof, bytes):
        ring_proof=bytes.fromhex(ring_proof)
    rvrf_proof= pedersen_proof +ring_proof
    return rvrf_proof


def pedersen_proof_to_hash(pedersen_proof:bytes|str)->bytes:
    """get the pedersen proof alone and return the 32 bytes hash"""
    if not isinstance(pedersen_proof, bytes):
        pedersen_proof=bytes.fromhex(pedersen_proof)

    if int.from_bytes(pedersen_proof[:32], 'little') == 0:
        # return ByteArray32(pedersen_proof[:32])
        return pedersen_proof[:32]

    vrf = PedersenVRF(Bandersnatch_TE_Curve, BandersnatchPoint)
    # extract the fist 32 bytes as it's the gamma
    gamma= BandersnatchPoint.string_to_point(pedersen_proof[:32])
    p_2h=vrf.proof_to_hash(gamma)
    return p_2h[:32]


#pedersen+ring_proof verification

def ring_vrf_proof_verify(context:bytes|str, ring_root:bytes|str, proof:bytes|str, alpha:bytes|str=b"")->bool: #context(add), ring_root, signature, message(alpha)
    if not isinstance(context,bytes):
        context=bytes.fromhex(context)
    if not isinstance(ring_root, bytes):
        ring_root=bytes.fromhex(ring_root)
    if not isinstance(proof, bytes):
        proof=bytes.fromhex(proof)
    if not isinstance(alpha, bytes):
        alpha=bytes.fromhex(alpha)

    pedersen_proof= proof[:192]
    vrf = PedersenVRF(Bandersnatch_TE_Curve, BandersnatchPoint)
    #get the input point
    input_point = BandersnatchPoint.encode_to_curve(alpha)

    #is pedersen proof valid
    p_proof_valid= vrf.verify(input_point, context , pedersen_proof)
    rel_to_proove=BandersnatchPoint.string_to_point(pedersen_proof[32:64])
    #Extract and verify the Ring proof
    ring_proof=proof[192:]
    proof_ptr = [H.bls_g1_decompress(ring_proof[:48]),
                 H.bls_g1_decompress(ring_proof[48 * 1: 48 * 2]),
                 H.bls_g1_decompress(ring_proof[48 * 2: 48 * 3]),
                 H.bls_g1_decompress(ring_proof[48 * 3:48 * 4]),
                 H.to_scalar_int(ring_proof[48 * 4 + (0 * 32): 48 * 4 + (1 * 32)]),
                 H.to_scalar_int(ring_proof[48 * 4 + (1 * 32): 48 * 4 + (2 * 32)]),
                 H.to_scalar_int(ring_proof[48 * 4 + (2 * 32): 48 * 4 + (3 * 32)]),
                 H.to_scalar_int(ring_proof[48 * 4 + (3 * 32): 48 * 4 + (4 * 32)]),
                 H.to_scalar_int(ring_proof[48 * 4 + (4 * 32): 48 * 4 + (5 * 32)]),
                 H.to_scalar_int(ring_proof[48 * 4 + (5 * 32): 48 * 4 + (6 * 32)]),
                 H.to_scalar_int(ring_proof[48 * 4 + (6 * 32): 48 * 4 + (7 * 32)]),
                 H.bls_g1_decompress(ring_proof[48 * 4 + (7 * 32):(48 * 4) + (7 * 32) + 48]),
                 H.to_scalar_int(ring_proof[(48 * 4) + (7 * 32) + 48: 48 * 4 + (7 * 32) + 48 + 32]),
                 H.bls_g1_decompress(ring_proof[48 * 4 + (7 * 32) + 48 + 32:-48]),
                 H.bls_g1_decompress(ring_proof[-48:])]

    rltn = (rel_to_proove.x, rel_to_proove.y) #relartion to proove
    res_plus_seed = TwistedEdwardCurve.add(SeedPoint, rltn)
    C_px, C_py, C_s = H.bls_g1_decompress(ring_root[:48]), H.bls_g1_decompress(ring_root[48:-48]), H.bls_g1_decompress(
        ring_root[-48:])
    fixed_cols_cmts = [C_px, C_py, C_s]
    verifier_key = {
        'g1': g1_points[0],
        'g2': H.altered_points(g2_points),
        'commitments': [H.to_int(each) for each in H.bls_projective_2_affine(fixed_cols_cmts)]
    }
    valid = Verify(proof_ptr, verifier_key, fixed_cols_cmts, rltn, res_plus_seed, SeedPoint, D)
    #is ring_proof valid
    ring_proof_valid= valid.is_signtaure_valid()
    return p_proof_valid and ring_proof_valid