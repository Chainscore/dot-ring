from dataclasses import dataclass
from typing import List, Any
from dot_ring.curve.point import CurvePoint
from dot_ring.ring_proof.constants import OMEGA_2048, S_PRIME, Blinding_Base, PaddingPoint, SeedPoint
from dot_ring.ring_proof.constraints.aggregation import aggregate_constraints
from dot_ring.ring_proof.constraints.constraints import RingConstraintBuilder
from dot_ring.ring_proof.curve.bandersnatch import TwistedEdwardCurve
from dot_ring.ring_proof.helpers import Helpers as H
from dot_ring.ring_proof.pcs.srs import srs
from dot_ring.ring_proof.pcs.kzg import KZG, Opening
from dot_ring.ring_proof.proof.aggregation_poly import AggPoly
from dot_ring.ring_proof.proof.linearization_poly import LAggPoly
from dot_ring.ring_proof.proof.quotient_poly import QuotientPoly
from dot_ring.ring_proof.transcript.phases import phase1_alphas, phase3_nu_vector
from dot_ring.ring_proof.transcript.transcript import Transcript
from dot_ring.ring_proof.verify import Verify
from dot_ring.vrf.pedersen.pedersen import PedersenVRF
from ..vrf import VRF
from py_ecc.optimized_bls12_381 import normalize as nm
from dot_ring.ring_proof.columns.columns import Column, PublicColumnBuilder as PC, WitnessColumnBuilder
from dot_ring.ring_proof.constants import D_512 as D
from .ring_root import RingRoot


@dataclass
class RingVRF(VRF):
    """
    Ring VRF implementation.

    This implementation provides Ring VRF operations combining
    Pedersen VRF proofs with ring signatures.
    
    Usage:
    >>> from dot_ring.curve.specs.bandersnatch import Bandersnatch
    >>> from dot_ring.vrf.ring.ring_vrf import RingVRF
    >>> proof = RingVRF[Bandersnatch].proof(alpha, ad, secret_key, producer_key, keys)
    >>> verified = RingVRF[Bandersnatch].verify(ad, ring_root, proof)
    
    Note: Ring VRF currently only supports Bandersnatch curve.
    """
    
    pedersen_proof: PedersenVRF
    c_b: Column
    c_accip: Column
    c_accx: Column
    c_accy: Column
    px_zeta: CurvePoint
    py_zeta: CurvePoint
    s_zeta: CurvePoint
    b_zeta: CurvePoint
    accip_zeta: CurvePoint
    accx_zeta: CurvePoint
    accy_zeta: CurvePoint
    c_q: Column
    l_zeta_omega: CurvePoint
    open_agg_zeta: Opening
    open_l_zeta_omega: Opening
    
    def to_bytes(self) -> bytes:
        """
        Serialize the Ring VRF proof to bytes.

        Returns:
            bytes: Bytes representation of the Ring VRF proof
        """
        return self.pedersen_proof.to_bytes() + bytes.fromhex(
            H.bls_g1_compress(self.c_b.commitment) +
            H.bls_g1_compress(self.c_accip.commitment) +
            H.bls_g1_compress(self.c_accx.commitment) +
            H.bls_g1_compress(self.c_accy.commitment) +
            H.to_bytes(self.px_zeta) +
            H.to_bytes(self.py_zeta) +
            H.to_bytes(self.s_zeta) +
            H.to_bytes(self.b_zeta) +
            H.to_bytes(self.accip_zeta) +
            H.to_bytes(self.accx_zeta) +
            H.to_bytes(self.accy_zeta) +
            H.bls_g1_compress(self.c_q.commitment) +
            H.to_bytes(self.l_zeta_omega) +
            H.bls_g1_compress(self.open_agg_zeta.proof) +
            H.bls_g1_compress(self.open_l_zeta_omega.proof)
        )
        
    @classmethod
    def from_bytes(cls, proof: bytes, skip_pedersen: bool = False) -> "RingVRF":
        """
        Deserialize the Ring VRF proof from bytes.

        Args:
            proof: Bytes representation of the Ring VRF proof
        Returns:
            RingVRF: Deserialized Ring VRF proof object
        """
        if not skip_pedersen:
            pedersen_proof = PedersenVRF[cls.cv].from_bytes(proof[:192])
            offset = 192
        else:
            pedersen_proof = None
            offset = 0
            
        commitment_size = 48  # Size of compressed G1 point
        
        c_b_commitment = H.bls_g1_decompress(proof[offset : offset + commitment_size].hex())
        offset += commitment_size
        c_accip_commitment = H.bls_g1_decompress(proof[offset : offset + commitment_size].hex())
        offset += commitment_size
        c_accx_commitment = H.bls_g1_decompress(proof[offset : offset + commitment_size].hex())
        offset += commitment_size
        c_accy_commitment = H.bls_g1_decompress(proof[offset : offset + commitment_size].hex())
        offset += commitment_size
        
        px_zeta = H.to_scalar_int(proof[offset : offset + 32])
        offset += 32
        py_zeta = H.to_scalar_int(proof[offset : offset + 32])
        offset += 32
        s_zeta = H.to_scalar_int(proof[offset : offset + 32])
        offset += 32
        b_zeta = H.to_scalar_int(proof[offset : offset + 32])
        offset += 32
        accip_zeta = H.to_scalar_int(proof[offset : offset + 32])
        offset += 32
        accx_zeta = H.to_scalar_int(proof[offset : offset + 32])
        offset += 32
        accy_zeta = H.to_scalar_int(proof[offset : offset + 32])
        offset += 32
        
        c_q_commitment = H.bls_g1_decompress(proof[offset : offset + commitment_size].hex())
        offset += commitment_size
        
        l_zeta_omega = H.to_scalar_int(proof[offset : offset + 32])
        offset += 32
        
        open_agg_zeta_commitment = H.bls_g1_decompress(proof[offset : offset + commitment_size].hex())
        offset += commitment_size
        open_l_zeta_omega_commitment = H.bls_g1_decompress(proof[offset : offset + commitment_size].hex())
        offset += commitment_size
        return cls(
            pedersen_proof=pedersen_proof,
            c_b=Column(name="c_b", evals=[], commitment=c_b_commitment),
            c_accip=Column(name="c_accip", evals=[], commitment=c_accip_commitment),
            c_accx=Column(name="c_accx", evals=[], commitment=c_accx_commitment),
            c_accy=Column(name="c_accy", evals=[], commitment=c_accy_commitment),
            px_zeta=px_zeta,
            py_zeta=py_zeta,
            s_zeta=s_zeta,
            b_zeta=b_zeta,
            accip_zeta=accip_zeta,
            accx_zeta=accx_zeta,
            accy_zeta=accy_zeta,
            c_q=Column(name="c_q", evals=[], commitment=c_q_commitment),
            l_zeta_omega=l_zeta_omega,
            # TODO: Fix Opening initialization; unsafe scalar 0 used temporarily
            open_agg_zeta=Opening(proof=open_agg_zeta_commitment, y=0), # We only need opening proof to verify
            open_l_zeta_omega=Opening(proof=open_l_zeta_omega_commitment, y=0) # We only need opening proof to verify
        )
    
    @classmethod
    def generate_bls_signature(
        cls,
        blinding_factor: int,
        producer_key: bytes | str,
        keys: List[Any] | str | bytes,
    ) -> bytes:
        """
        Returns the Ring Proof as an output
        """
        producer_key_point = cls.cv.point.string_to_point(producer_key)

        if not producer_key_point or producer_key_point == "INVALID":
            producer_key_point = cls.cv.point(PaddingPoint[0], PaddingPoint[1])

        producer_key_pt = (producer_key_point.x, producer_key_point.y)
        keys_as_bs_points = []

        for key in keys:
            point = cls.cv.point.string_to_point(key)
            keys_as_bs_points.append((point.x, point.y))

        ring_root = PC()  # ring_root builder
        fixed_cols = ring_root.build(keys_as_bs_points)
        s_v = fixed_cols[-1].evals
        producer_index = keys_as_bs_points.index(producer_key_pt)
        witness_obj = WitnessColumnBuilder(keys_as_bs_points, s_v, producer_index, blinding_factor)
        witness_res = witness_obj.build()
        witness_relation_res = witness_obj.result(Blinding_Base)
        Result_plus_Seed = witness_obj.result_p_seed(witness_relation_res)
        constraints = RingConstraintBuilder(
            Result_plus_Seed,
            fixed_cols[0].coeffs,
            fixed_cols[1].coeffs,
            fixed_cols[2].coeffs,
            witness_res[0].coeffs,
            witness_res[1].coeffs,
            witness_res[2].coeffs,
            witness_res[3].coeffs,
        )

        constraint_dict = constraints.compute()
        fixed_col_commits = [
            H.to_int(nm(fixed_cols[0].commitment)),
            H.to_int(nm(fixed_cols[1].commitment)),
            H.to_int(nm(fixed_cols[2].commitment)),
        ]

        ws = witness_res
        witness_commitments = [
            H.to_int(nm(ws[0].commitment)),
            H.to_int(nm(ws[-1].commitment)),
            H.to_int(nm(ws[1].commitment)),
            H.to_int(nm(ws[2].commitment)),
        ]

        vk = {
            "g1": srs.g1_points[0],
            "g2": H.altered_points(srs.g2_points),
            "commitments": fixed_col_commits,
        }
        t = Transcript(S_PRIME, b"Bandersnatch_SHA-512_ELL2")
        t, alpha = phase1_alphas(t, vk, witness_relation_res, witness_commitments)

        cd = constraint_dict
        c_polys = [cd[val] for val in cd]
        C_agg = aggregate_constraints(c_polys, alpha, OMEGA_2048, S_PRIME)
        qp = QuotientPoly()
        Q_p, C_q = qp.quotient_poly(C_agg)
        C_q_commitment = Column(name="C_q", evals=[], commitment=C_q)
        C_q_nm = nm(C_q)
        l_obj = LAggPoly(t, H.to_int(C_q_nm), fixed_cols, ws, alpha)
        current_t, zeta, rel_poly_evals, l_agg, zeta_omega, l_zw = l_obj.l_agg_poly()
        _, _, phi_z, phi_zw = AggPoly.proof_contents_phi(zeta, zeta_omega, l_agg, fixed_cols, ws, Q_p, phase3_nu_vector(current_t, list(rel_poly_evals.values()), l_zw))
        [p_x_zeta, p_y_zeta, s_zeta, b_zeta, acc_ip_zeta, acc_x_zeta, acc_y_zeta] = list(rel_poly_evals.values())
        c_b, c_acc_x, c_acc_y, c_acc_ip = ws[0], ws[1], ws[2], ws[3]
        return (c_b, c_acc_ip, c_acc_x, c_acc_y, p_x_zeta, p_y_zeta, s_zeta, b_zeta, acc_ip_zeta, acc_x_zeta, acc_y_zeta, C_q_commitment, l_zw, phi_z, phi_zw)

    def verify_ring_proof(
        self,
        message: bytes | CurvePoint, 
        ring_root: RingRoot | bytes, 
    ) -> bool:
        """
        Verifies the Ring Proof
        """
        # Decompress ring_root once at the start
        if isinstance(ring_root, bytes):
            ring_root = RingRoot.from_bytes(ring_root)
        fixed_cols_cmts = [ring_root.px.commitment, ring_root.py.commitment, ring_root.s.commitment]
        
        if isinstance(message, bytes):
            message = self.cv.point.string_to_point(message)  # relation to proove

        rltn = (message.x, message.y)  # relartion to proove
        res_plus_seed = TwistedEdwardCurve.add(SeedPoint, rltn)
        
        verifier_key = {
            "g1": srs.g1_points[0],
            "g2": H.altered_points(srs.g2_points),
            "commitments": [
                H.to_int(each) for each in H.bls_projective_2_affine(fixed_cols_cmts)
            ],
        }
        
        return Verify(
            (
                self.c_b.commitment,
                self.c_accip.commitment,
                self.c_accx.commitment,
                self.c_accy.commitment,
                self.px_zeta,
                self.py_zeta,
                self.s_zeta,
                self.b_zeta,
                self.accip_zeta,
                self.accx_zeta,
                self.accy_zeta,
                self.c_q.commitment,
                self.l_zeta_omega,
                self.open_agg_zeta.proof,
                self.open_l_zeta_omega.proof,
                ), verifier_key, fixed_cols_cmts, rltn, res_plus_seed, SeedPoint, D
        ).is_valid()

    @classmethod
    def construct_ring_root(
        cls,
        keys: List[bytes], 
    ) -> RingRoot:
        """
        Constructs the Ring Root
        """
        keys_as_bs_points = []
        for key in keys:
            point = cls.cv.point.string_to_point(key)

            if not point or point == "INVALID":
                keys_as_bs_points.append((PaddingPoint[0], PaddingPoint[1]))

            else:
                keys_as_bs_points.append((point.x, point.y))

        ring_root = PC()  # ring_root builder
        fixed_cols = ring_root.build(keys_as_bs_points)

        return RingRoot(*fixed_cols)

    @classmethod
    def proof(
        cls,
        alpha: bytes,
        ad: bytes,
        secret_key: bytes,
        producer_key: bytes,
        keys: List[bytes],
    ) -> "RingVRF":
        """
        Generate ring VRF proof (pedersen vrf proof + ring_proof)
        """
        # pedersen_proof
        pedersen_proof = PedersenVRF[cls.cv].proof(alpha, secret_key, ad)

        # ring_proof
        ring_proof = cls.generate_bls_signature(
            pedersen_proof._blinding_factor, producer_key, keys
        )

        return cls(pedersen_proof, *ring_proof)
        
    @classmethod
    def parse_keys(cls, keys: bytes) -> List[bytes]:
        """Parse a bytes object containing concatenated keys into a list of individual keys.

        Args:
            keys (bytes): A bytes object containing concatenated keys.

        Returns:
            List[bytes]: A list of individual keys extracted from the input bytes object.
        """
        return [
            keys[32 * i : 32 * (i + 1)] for i in range(len(keys) // 32)
        ]
        

    def verify(
        self,
        input: bytes,
        ad_data: bytes,
        ring_root: RingRoot | bytes,
    ) -> bool:
        """
        Verify ring VRF proof (pedersen_proof + ring_proof)
        """
        # Decompress ring_root once at the start
        if isinstance(ring_root, bytes):
            ring_root = RingRoot.from_bytes(ring_root)
        
        # is pedersen proof valid
        p_proof_valid = self.pedersen_proof.verify(input, ad_data)
        ring_proof_valid = self.verify_ring_proof(self.pedersen_proof.blinded_pk, ring_root)

        return p_proof_valid and ring_proof_valid