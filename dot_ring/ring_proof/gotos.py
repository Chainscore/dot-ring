
from typing import List
from jam.ring_vrf.ring_proof.short_weierstrass.banders import TwistedEdwardCurve
from jam.types.base import ByteArray32
from jam.types.protocol.crypto import BandersnatchPublic
from jam.ring_vrf.ring_proof.columns.columns import PublicColumnBuilder as PC
from jam.ring_vrf.ring_proof.pcs.load_powers import g1_points, g2_points
from jam.ring_vrf.ring_proof.transcript.phases import phase1_alphas
from jam.ring_vrf.ring_proof.transcript.transcript import Transcript
# from jam.ring_vrf.ring_proof.short_weierstrass.curve import ShortWeierstrassCurve as sw
from jam.ring_vrf.ring_proof.constants import Blinding_Base, S_PRIME, OMEGA_2048, SeedPoint
from jam.ring_vrf.ring_proof.columns.columns import WitnessColumnBuilder, PublicColumnBuilder
from jam.ring_vrf.ring_proof.constraints.constraints import RingConstraintBuilder
from jam.ring_vrf.ring_proof.helpers import Helpers as H
from py_ecc.optimized_bls12_381 import normalize as nm
from jam.ring_vrf.ring_proof.constraints.aggregation import aggregate_constraints
from jam.ring_vrf.ring_proof.proof.quotient_poly import QuotientPoly
from jam.ring_vrf.ring_proof.proof.linearization_poly import LAggPoly
from jam.ring_vrf.ring_proof.proof.aggregation_poly_and_proof_gtn import AggPoly
from jam.ring_vrf.ring_proof.verfiey import Verify
from jam.ring_vrf.ring_proof.constants import D_512 as D
from jam.ring_vrf.curve.specs.bandersnatch import (
    Bandersnatch_TE_Curve,
    BandersnatchPoint,
)
from jam.ring_vrf.pedersen.pedersen import PedersenVRF


def generate_bls_signature(secret_t,producer_key, keys: List[BandersnatchPublic]):
    """
    get the all the data needed and
    return the signature as an output
    """
    # signature = func() #make the call or logic u want
    # return signature
    producer_key_point=BandersnatchPoint.string_to_point(bytes(producer_key))
    producer_key_pt= producer_key_point.x, producer_key_point.y
    keys_as_bs_points = []

    for key in keys:
        point = BandersnatchPoint.string_to_point(bytes(key))  # or take key[2:] by skipping '0x'
        keys_as_bs_points.append((point.x, point.y))

    ring_root = PC()  # ring_root builder
    fixed_cols = ring_root.build(keys_as_bs_points)

    ring_root_bs = bytearray.fromhex(H.bls_g1_compress(fixed_cols[0].commitment)).hex() + bytearray.fromhex(
        H.bls_g1_compress(fixed_cols[1].commitment)).hex() + bytearray.fromhex(
        H.bls_g1_compress(fixed_cols[2].commitment)).hex()

    s_v = fixed_cols[-1].evals
    producer_index= keys_as_bs_points.index(producer_key_pt)
    witness_obj = WitnessColumnBuilder(keys_as_bs_points, s_v, producer_index, secret_t)
    witness_res = witness_obj.build()
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
    qp = QuotientPoly()
    Q_p, C_q = qp.quotient_poly(C_agg)
    C_q_nm = nm(C_q)
    l_obj = LAggPoly(t, H.to_int(C_q_nm), fixed_cols, ws, alpha)
    current_t, zeta, rel_poly_evals, l_agg, zeta_omega, l_zw = l_obj.l_agg_poly()
    obj = AggPoly(current_t, zeta, fixed_cols, ws, Q_p, C_q, rel_poly_evals, l_agg, zeta_omega, l_zw)

    cf_vs, proof_ptr, proof_bs = obj.construct_proof()
    return proof_bs #bytess string


def construct_ring_root(keys: List[BandersnatchPublic]):
    """
    get the data needed and construct the rng root
    """
    # ring_root= func() make the call ore logic u want
    #return ring_root
    keys_as_bs_points = []
    for key in keys:
        point = BandersnatchPoint.string_to_point(bytes(key))  # or take key[2:] by skipping '0x'
        keys_as_bs_points.append((point.x, point.y))

    ring_root = PC()  # ring_root builder
    fixed_cols = ring_root.build(keys_as_bs_points)

    fxd_col_cs = bytearray.fromhex(H.bls_g1_compress(fixed_cols[0].commitment))+ bytearray.fromhex(
        H.bls_g1_compress(fixed_cols[1].commitment))+ bytearray.fromhex(
        H.bls_g1_compress(fixed_cols[2].commitment))
    return fxd_col_cs


def verify_signature(message, ring_root, proof):
    """
    get the bls signature, other params if needed and verify it
    """
    # is_valid=func() # make the func call or logic u want
    # return is_valid
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


def ring_vrf_proof(alpha, add, blinding_factor, producer_key, keys:List[BandersnatchPublic]):
    """get the args u want and generate the
    ring_vrf_proof (pedersen vrf proof + ring_proof ) \
    which of length 784 bytes"""

    #pedersen_proof=get the pedersen proof
    vrf = PedersenVRF(Bandersnatch_TE_Curve, BandersnatchPoint)
    blinding_f_int = (
            int.from_bytes(blinding_factor)
            % Bandersnatch_TE_Curve.ORDER
    )
    secret_scalar = (
            int.from_bytes(producer_key)
            % Bandersnatch_TE_Curve.ORDER
    )
    output_point, proof = vrf.prove(
        alpha,
        secret_scalar,
        add,
        blinding_f_int,
    )
    pedersen_proof=output_point.point_to_string().hex()+proof[0].point_to_string().hex() +proof[1].point_to_string().hex()+proof[2].point_to_string().hex() +H.to_bytes(proof[3]) +H.to_bytes(proof[4])

    #ring_proof= get the ring_signature
    ring_proof= generate_bls_signature(blinding_f_int,producer_key, keys)
    rvrf_proof= pedersen_proof +ring_proof
    return rvrf_proof


def pedersen_proof_to_hash(pedersen_proof):
    """get the pedersen proof alone and return the 32 bytes hash"""
    if int.from_bytes(pedersen_proof[:32], 'little') == 0:
        return ByteArray32(pedersen_proof[:32])
    vrf = PedersenVRF(Bandersnatch_TE_Curve, BandersnatchPoint)
    # extract the fist 32 bytes as it's the gamma
    gamma= BandersnatchPoint.string_to_point(pedersen_proof[:32])
    p_2h=vrf.proof_to_hash(gamma)
    return p_2h[:32]


#pedersen+ring_proof verification

def ring_vrf_proof_verify(context, ring_root, proof, alpha=b""): #context(add), ring_root, signature, message(alpha)

    pedersen_proof= proof[:192]
    vrf = PedersenVRF(Bandersnatch_TE_Curve, BandersnatchPoint)
    #get the input point
    input_point = BandersnatchPoint.encode_to_curve(alpha)
    output_point=BandersnatchPoint.string_to_point(pedersen_proof[32*0:32*1]) #O.p
    rel_to_proove = BandersnatchPoint.string_to_point(pedersen_proof[32*1:32*2]) #Y'
    R=BandersnatchPoint.string_to_point(pedersen_proof[32*2:32*3]) #R
    Ok=BandersnatchPoint.string_to_point(pedersen_proof[32*3:32*4])#Ok
    S=H.bytes_to_int(pedersen_proof[32*4:32*5])
    Sb=H.bytes_to_int(pedersen_proof[32*5:32*6])

    proof_tup=(rel_to_proove,R, Ok, S, Sb)

    #is pedersen proof valid
    p_proof_valid= vrf.verify(
        input_point, context , output_point, proof_tup
    )

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




#have to make these as interfaces and put the logic in diff area
#have to make the preprocessing well in such a way that they should work as like ietf and pedersens
#options
# put the interface logic in the vrf file itself
# or create a separate calls for ring_vrf inside the vrf file
#we can include one more fun for verifying the ring_vrf proof (pedersen+ring_proof)
