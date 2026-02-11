from dataclasses import dataclass
from typing import Any, cast

from py_ecc.optimized_bls12_381 import normalize as nm

from dot_ring.curve.point import CurvePoint
from dot_ring.ring_proof.columns.columns import Column, WitnessColumnBuilder
from dot_ring.ring_proof.constants import (
    S_PRIME,
    Blinding_Base,
    PaddingPoint,
    SeedPoint,
)
from dot_ring.ring_proof.constraints.aggregation import aggregate_constraints
from dot_ring.ring_proof.constraints.constraints import RingConstraintBuilder
from dot_ring.ring_proof.curve.bandersnatch import TwistedEdwardCurve
from dot_ring.ring_proof.helpers import Helpers as H
from dot_ring.ring_proof.pcs.kzg import Opening
from dot_ring.ring_proof.pcs.srs import srs
from dot_ring.ring_proof.proof.aggregation_poly import AggPoly
from dot_ring.ring_proof.proof.linearization_poly import LAggPoly
from dot_ring.ring_proof.proof.quotient_poly import QuotientPoly
from dot_ring.ring_proof.transcript.phases import phase1_alphas, phase3_nu_vector
from dot_ring.ring_proof.transcript.transcript import Transcript
from dot_ring.ring_proof.verify import Verify
from dot_ring.vrf.pedersen.pedersen import PedersenVRF

from ..vrf import VRF
from .ring_root import Ring, RingRoot


@dataclass
class RingVRF(VRF[Any]):
    """
    Ring VRF implementation.

    This implementation provides Ring VRF operations combining
    Pedersen VRF proofs with ring signatures.

    Usage:
    >>> from dot_ring.curve.specs.bandersnatch import Bandersnatch
    >>> from dot_ring.vrf.ring.ring_vrf import RingVRF
    >>> proof = RingVRF[Bandersnatch].prove(alpha, ad, secret_key, producer_key, keys)
    >>> verified = RingVRF[Bandersnatch].verify(ad, ring_root, proof)

    Note: Ring VRF currently only supports Bandersnatch curve.
    """

    pedersen_proof: PedersenVRF | None
    c_b: Column
    c_accip: Column
    c_accx: Column
    c_accy: Column
    px_zeta: int
    py_zeta: int
    s_zeta: int
    b_zeta: int
    accip_zeta: int
    accx_zeta: int
    accy_zeta: int
    c_q: Column
    l_zeta_omega: int
    open_agg_zeta: Opening
    open_l_zeta_omega: Opening

    def to_bytes(self) -> bytes:
        """
        Serialize the Ring VRF proof to bytes.

        Returns:
            bytes: Bytes representation of the Ring VRF proof
        """
        assert self.c_b.commitment is not None
        assert self.c_accip.commitment is not None
        assert self.c_accx.commitment is not None
        assert self.c_accy.commitment is not None
        assert self.c_q.commitment is not None
        assert self.open_agg_zeta.proof is not None
        assert self.open_l_zeta_omega.proof is not None

        assert self.pedersen_proof is not None
        return self.pedersen_proof.to_bytes() + bytes.fromhex(
            H.bls_g1_compress(cast(tuple, self.c_b.commitment))
            + H.bls_g1_compress(cast(tuple, self.c_accip.commitment))
            + H.bls_g1_compress(cast(tuple, self.c_accx.commitment))
            + H.bls_g1_compress(cast(tuple, self.c_accy.commitment))
            + H.to_bytes(self.px_zeta)
            + H.to_bytes(self.py_zeta)
            + H.to_bytes(self.s_zeta)
            + H.to_bytes(self.b_zeta)
            + H.to_bytes(self.accip_zeta)
            + H.to_bytes(self.accx_zeta)
            + H.to_bytes(self.accy_zeta)
            + H.bls_g1_compress(cast(tuple, self.c_q.commitment))
            + H.to_bytes(self.l_zeta_omega)
            + H.bls_g1_compress(cast(tuple, self.open_agg_zeta.proof))
            + H.bls_g1_compress(cast(tuple, self.open_l_zeta_omega.proof))
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
            pedersen_proof = PedersenVRF[cls.cv].from_bytes(proof[:192])  # type: ignore[name-defined]
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
            open_agg_zeta=Opening(proof=open_agg_zeta_commitment, y=0),  # We only need opening proof to verify
            open_l_zeta_omega=Opening(proof=open_l_zeta_omega_commitment, y=0),  # We only need opening proof to verify
        )

    @classmethod
    def generate_bls_signature(
        cls,
        blinding_factor: int,
        producer_key: bytes | str,
        ring: Ring,
        transcript_challenge: bytes = b"Bandersnatch_SHA-512_ELL2",
        ring_root: RingRoot | None = None,
    ) -> tuple[
        Column,
        Column,
        Column,
        Column,
        int,
        int,
        int,
        int,
        int,
        int,
        int,
        Column,
        int,
        Any,
        Any,
    ]:
        """
        Returns the Ring Proof as an output.

        Args:
            blinding_factor: Blinding factor from Pedersen VRF
            producer_key: Public key of the prover
            ring: Ring object containing member keys and params
            transcript_challenge: Challenge for Fiat-Shamir
            ring_root: Optional pre-computed ring root for performance
        """
        # Use params from the ring object
        params = ring.params
        producer_key_point = cls.cv.point.string_to_point(producer_key)

        if isinstance(producer_key_point, str) or producer_key_point.is_identity():
            producer_key_point = cls.cv.point(PaddingPoint[0], PaddingPoint[1])

        producer_key_pt = (
            cast(int, producer_key_point.x),
            cast(int, producer_key_point.y),
        )

        if not ring_root:
            ring_root = RingRoot.from_ring(ring, params)  # ring_root builder

        s_v = ring_root.s.evals
        producer_index = ring.nm_points.index(producer_key_pt)
        witness_obj = WitnessColumnBuilder.from_params(
            ring.nm_points,
            s_v,
            producer_index,
            blinding_factor,
            params,
        )
        witness_res = witness_obj.build()
        witness_relation_res = witness_obj.result(Blinding_Base)
        Result_plus_Seed = witness_obj.result_p_seed(witness_relation_res)
        constraints = RingConstraintBuilder(
            Result_plus_Seed=Result_plus_Seed,  # type: ignore
            px=cast(list[int], ring_root.px.coeffs),
            py=cast(list[int], ring_root.py.coeffs),
            s=cast(list[int], ring_root.s.coeffs),
            b=cast(list[int], witness_res[0].coeffs),
            acc_x=cast(list[int], witness_res[1].coeffs),
            acc_y=cast(list[int], witness_res[2].coeffs),
            acc_ip=cast(list[int], witness_res[3].coeffs),
            params=params,
        )

        constraint_dict = constraints.compute()
        fixed_col_commits = [
            H.to_int(nm(ring_root.px.commitment)),
            H.to_int(nm(ring_root.py.commitment)),
            H.to_int(nm(ring_root.s.commitment)),
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
        t = Transcript(S_PRIME, transcript_challenge)
        t, alpha = phase1_alphas(t, vk, witness_relation_res, witness_commitments)

        cd = constraint_dict
        c_polys = [cd[val] for val in cd]
        C_agg = aggregate_constraints(c_polys, alpha, params.radix_omega, S_PRIME, domain=params.domain)
        qp = QuotientPoly(params.domain_size)
        Q_p, C_q = qp.quotient_poly(C_agg)
        C_q_commitment = Column(name="C_q", evals=[], commitment=C_q)
        C_q_nm = nm(C_q)
        l_obj = LAggPoly(
            t,
            list(H.to_int(C_q_nm)),
            list([ring_root.px, ring_root.py, ring_root.s]),
            list(ws),
            alpha,
            domain=params.domain,
            omega=params.omega,
            padding_rows=params.padding_rows,
        )
        current_t, zeta, rel_poly_evals, l_agg, zeta_omega, l_zw = l_obj.l_agg_poly()
        _, _, phi_z, phi_zw = AggPoly.proof_contents_phi(
            zeta,
            zeta_omega,
            l_agg,
            list([ring_root.px, ring_root.py, ring_root.s]),
            list(ws),
            Q_p,
            phase3_nu_vector(current_t, list(rel_poly_evals.values()), l_zw),
        )
        [
            p_x_zeta,
            p_y_zeta,
            s_zeta,
            b_zeta,
            acc_ip_zeta,
            acc_x_zeta,
            acc_y_zeta,
        ] = list(rel_poly_evals.values())
        c_b, c_acc_x, c_acc_y, c_acc_ip = ws[0], ws[1], ws[2], ws[3]
        return (
            c_b,
            c_acc_ip,
            c_acc_x,
            c_acc_y,
            p_x_zeta,
            p_y_zeta,
            s_zeta,
            b_zeta,
            acc_ip_zeta,
            acc_x_zeta,
            acc_y_zeta,
            C_q_commitment,
            l_zw,
            phi_z,
            phi_zw,
        )

    def verify_ring_proof(
        self,
        message: bytes | CurvePoint,
        ring: Ring,
        ring_root: RingRoot,
    ) -> bool:
        """
        Verifies the Ring Proof
        """
        fixed_cols_cmts = [
            ring_root.px.commitment,
            ring_root.py.commitment,
            ring_root.s.commitment,
        ]

        if isinstance(message, bytes):
            message_pt = self.cv.point.string_to_point(message)  # relation to proove
            if isinstance(message_pt, str):
                raise ValueError("Invalid message point")
            message = message_pt

        rltn = (message.x, message.y)  # relartion to proove
        res_plus_seed = TwistedEdwardCurve.add(SeedPoint, rltn)

        # Ensure commitments are not None
        fixed_cols_cmts_safe = []
        for c in fixed_cols_cmts:
            assert c is not None
            fixed_cols_cmts_safe.append(c)
        comm_keys_affine = H.bls_projective_2_affine(cast(list[Any], fixed_cols_cmts_safe))
        comm_keys_int = [H.to_int(pt) for pt in comm_keys_affine]
        verifier_key: dict[str, Any] = {
            "g1": srs.g1_points[0],
            "g2": cast(Any, H.altered_points(srs.g2_points)),  # type: ignore
            "commitments": comm_keys_int,
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
            ),
            verifier_key,
            fixed_cols_cmts,
            rltn,
            res_plus_seed,
            SeedPoint,
            ring.params.domain,
            padding_rows=ring.params.padding_rows,
        ).is_valid()

    @classmethod
    def prove(
        cls,
        alpha: bytes,
        ad: bytes,
        secret_key: bytes,
        producer_key: bytes,
        ring: Ring,
        ring_root: RingRoot | None = None,
    ) -> "RingVRF":
        """
        Generate ring VRF proof (pedersen vrf proof + ring_proof).

        Args:
            alpha: VRF input
            ad: Additional data
            secret_key: Prover's secret key
            producer_key: Prover's public key
            ring: Ring object containing member keys. Params are auto-constructed if not provided to Ring.
            ring_root: Pre-computed ring root. If provided, skips expensive ring column construction (~335ms for 1023 members).

        Returns:
            RingVRF proof

        Examples:
            >>> ring = Ring(keys)  # Automatically determines optimal domain size
            >>> proof = RingVRF[Bandersnatch].prove(alpha, ad, sk, pk, ring)
        """
        pedersen_proof = PedersenVRF[cast(Any, cls).cv].prove(alpha, secret_key, ad)  # type: ignore[misc]

        ring_proof = cls.generate_bls_signature(pedersen_proof._blinding_factor, producer_key, ring=ring, ring_root=ring_root)

        return cls(pedersen_proof, *ring_proof)

    @classmethod
    def parse_keys(cls, keys: bytes) -> list[bytes]:
        """Parse a bytes object containing concatenated keys into a list of individual keys.

        Args:
            keys (bytes): A bytes object containing concatenated keys.

        Returns:
            List[bytes]: A list of individual keys extracted from the input bytes object.
        """
        return [keys[32 * i : 32 * (i + 1)] for i in range(len(keys) // 32)]

    def verify(self, input: bytes, ad_data: bytes, ring: Ring, ring_root: RingRoot) -> bool:
        """
        Verify ring VRF proof (pedersen_proof + ring_proof)
        """
        if self.pedersen_proof is None:
            raise ValueError("Pedersen proof is missing")
        p_proof_valid = self.pedersen_proof.verify(input, ad_data)
        ring_proof_valid = self.verify_ring_proof(self.pedersen_proof.blinded_pk, ring, ring_root)

        return p_proof_valid and ring_proof_valid
