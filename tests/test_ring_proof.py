import time
import json
import os
import pytest
start_time=time.time()
from dot_ring.ring_proof.pcs.load_powers import g1_points, g2_points
from dot_ring.ring_proof.transcript.phases import phase1_alphas
from dot_ring.ring_proof.transcript.transcript import Transcript
from dot_ring.curve.short_weierstrass.curve import ShortWeierstrassCurve as sw
from dot_ring.ring_proof.constants import Blinding_Base, S_PRIME, OMEGA_2048, SeedPoint
from dot_ring.ring_proof.columns.columns import WitnessColumnBuilder, PublicColumnBuilder
from dot_ring.ring_proof.constraints.constraints import RingConstraintBuilder
from dot_ring.ring_proof.helpers import Helpers as H
from py_ecc.optimized_bls12_381 import normalize as nm, normalize
from dot_ring.ring_proof.constraints.aggregation import aggregate_constraints
from dot_ring.ring_proof.proof.quotient_poly import QuotientPoly
from dot_ring.ring_proof.proof.linearization_poly import LAggPoly
from dot_ring.ring_proof.proof.aggregation_poly import AggPoly
from dot_ring.ring_proof.verify import Verify
from dot_ring.ring_proof.constants import D_512 as D

from dot_ring.curve.specs.bandersnatch import (
    Bandersnatch_TE_Curve,
    BandersnatchPoint,
)

def test_ring_proof():
    file_path = '/home/siva/PycharmProjects/dot_ring/tests/ark-vrf/bandersnatch_ed_sha512_ell2_ring.json'
    with open(file_path, 'r') as f:
        data = json.load(f)

    for index in range(len(data)-6):

        if index < 0 or index >= len(data):
            raise IndexError("Index out of range")

        item = data[index]
        secret_BA = item['blinding']

        secret_B = bytes.fromhex(secret_BA)

        secret_t = int.from_bytes(secret_B, 'little')

        print("secret_t:", secret_t)

        block_producer = item['pk']

        pk_ring = item['ring_pks']

        pk_list = []
        pk_x_y_list_sw= []
        pk_x_y_list_te=[]

        frm = 0
        to = 64
        # print(len(pk_ring))
        for i in range(len(pk_ring) // 64):
            pk_list.append(pk_ring[frm:to])
            frm = to
            to += 64

        count = 0
        for string in pk_list:
            try:
                pk = BandersnatchPoint.string_to_point(string)
                pk_x_y_list_sw.append(sw.from_twisted_edwards((pk.x, pk.y)))
                pk_x_y_list_te.append((pk.x, pk.y))
            except ValueError as e:
                count += 1

        producer_index = pk_list.index(block_producer)

        # single test file

        # buillding the vectors, polys, commitments
        f_c_s = PublicColumnBuilder()
        List_of_PK = pk_x_y_list_te
        fixed_cols = f_c_s.build(List_of_PK)
        s_v = fixed_cols[-1].evals
        witness_obj = WitnessColumnBuilder(List_of_PK, s_v, producer_index, secret_t)
        witness_res = witness_obj.build()
        witness_relation_res = witness_obj.result(Blinding_Base)
        Result_plus_Seed = witness_obj.result_p_seed(witness_relation_res)
        print("Relation to proove:", BandersnatchPoint(witness_relation_res[0], witness_relation_res[1]).point_to_string().hex())

        # building constraints
        constraints = RingConstraintBuilder(Result_plus_Seed, fixed_cols[0].coeffs, fixed_cols[1].coeffs,
                                            fixed_cols[2].coeffs, witness_res[0].coeffs, witness_res[1].coeffs,
                                            witness_res[2].coeffs, witness_res[3].coeffs)


        constraint_dict = constraints.compute()

        # consraints Agrregation
        # convert the g2 points for fs
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


        print("Proof point representation:", proof_ptr)
        print("proof_byte_string:", proof_bs)

        assert proof_bs == item['ring_proof']
        print(f"Is proof {index} matching:", proof_bs == item['ring_proof'])
        # # proof verification
        cnd_res = witness_relation_res
        vfr = Verify(proof_ptr, vk, fixed_cols, cnd_res, Result_plus_Seed, SeedPoint, D)
        print("proof1:", vfr.evaluation_of_linearization_poly_at_zeta_omega())
        print("prioof2:", vfr.evaluation_of_quotient_poly_at_zeta())
        print(f"Is signature {index} valid:", vfr.is_signtaure_valid())
        print(f"Test_Case {index}:✅")

