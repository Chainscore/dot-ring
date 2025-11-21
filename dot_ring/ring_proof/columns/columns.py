from __future__ import annotations
from dataclasses import dataclass
import json
import os
from typing import List, Tuple
from dot_ring.ring_proof.helpers import Helpers as H
from dot_ring.ring_proof.pcs.load_powers import g1_points, g2_points
from dot_ring.ring_proof.polynomial.interpolation import poly_interpolate_fft
from dot_ring.ring_proof.pcs.kzg import KZG
from dot_ring.ring_proof.curve.bandersnatch import TwistedEdwardCurve as TE

h_vec = json.load(open(os.path.join(os.path.dirname(__file__), "h_vec.json"), "r"))

from dot_ring.ring_proof.constants import (
    S_PRIME,
    OMEGA as OMEGA,
    Blinding_Base,
    PaddingPoint,
    SeedPoint,
    MAX_RING_SIZE,
    SIZE,
)

Scalar = int
G1Point = Tuple


@dataclass(slots=True)
class Column:
    name: str
    evals: List[int]
    coeffs: List[int] | None = None
    commitment: G1Point | None = None
    size: int = SIZE

    def interpolate(self, domain_omega: int = OMEGA, prime: int = S_PRIME) -> None:
        """Fill `self.coeffs` from `self.evals` using FFT interpolation."""
        if self.coeffs is None:
            self.evals += [0] * (SIZE - len(self.evals))
            self.coeffs = poly_interpolate_fft(self.evals, domain_omega, prime)

    def commit(self, kzg: KZG | None = None) -> None:
        if self.coeffs is None:
            raise ValueError("call interpolate() first")
        if self.commitment is None:
            kzg = kzg or _get_default_kzg()
            self.commitment = kzg.commit(self.coeffs)


def _get_default_kzg() -> KZG:
    # Build an SRS with proper Jacobian conversion via the helper.
    from dot_ring.ring_proof.pcs.kzg import SRS

    return KZG(SRS(g1_points, g2_points))


@dataclass(slots=True)
class PublicColumnBuilder:
    size: int = SIZE
    prime: int = S_PRIME
    omega: int = OMEGA

    def _pad_ring_with_padding_point(
        self, pk_ring: List[Tuple[int, int]], size: int = MAX_RING_SIZE
    ) -> List[Tuple[int, int]]:
        """Pad ring in‑place with the special padding point until size."""
        # padding_sw = sw.from_twisted_edwards(PaddingPoint)
        padding_sw = PaddingPoint
        while len(pk_ring) < MAX_RING_SIZE:
            pk_ring.append(padding_sw)
        return pk_ring

    def _h_vector(self, blinding_base=Blinding_Base) -> List[Tuple[int, int]]:
        """Return `[2⁰·H, 2¹·H, …]` in short‑Weierstrass coords."""
        # sw_bb = sw.from_twisted_edwards(blinding_base)
        sw_bb = blinding_base
        # print("Blinding Base:",sw_bb)
        res = [TE.mul(pow(2, i, S_PRIME), sw_bb) for i in range(self.size)]
        return res  # B_Neck

    def build(
        self, ring_pk: List[Tuple[int, int]], kzg: KZG | None = None
    ) -> tuple[Column, Column, Column]:
        """Return (Px, Py, s) columns fully committed."""
        if len(ring_pk) < MAX_RING_SIZE:
            ring_pk = self._pad_ring_with_padding_point(ring_pk)
        # 1. ensure ring size
        for i in range(self.size - 4 - len(ring_pk)):
            ring_pk.append(h_vec[i])
        ring_pk.extend([(0, 0)] * 4)

        # 2. unzip into x/y vectors
        px, py = H.unzip(ring_pk)

        # 3. selector vector
        sel = [1 if i < MAX_RING_SIZE else 0 for i in range(self.size)]

        # 4. Columns
        col_px = Column("Px", px)
        col_py = Column("Py", py)
        col_s = Column("s", sel)
        for col in (col_px, col_py, col_s):
            col.interpolate(self.omega, self.prime)
            col.commit(kzg)
        return col_px, col_py, col_s


@dataclass(slots=True)
class WitnessColumnBuilder:
    ring_pk: List[Tuple[int, int]]
    selector_vector: List[int]
    producer_index: int
    secret_t: int
    size: int = SIZE
    omega: int = OMEGA
    prime: int = S_PRIME

    def _bits_vector(self) -> List[int]:
        bv = [1 if i == self.producer_index else 0 for i in range(MAX_RING_SIZE)]
        t_bits = bin(self.secret_t)[2:][::-1]
        bv.extend(int(b) for b in t_bits)
        while len(bv) < self.size - 4:
            bv.append(0)
        bv.append(0)  # padding bit
        return bv

    def _conditional_sum_accumulator(
        self, b_vector: List[int]
    ) -> tuple[List[int], List[int]]:
        seed_sw = SeedPoint

        acc = [seed_sw]
        for i in range(1, self.size - 3):
            next_pt = (
                acc[i - 1]
                if b_vector[i - 1] == 0
                else TE.add(acc[i - 1], self.ring_pk[i - 1])
            )
            acc.append(next_pt)
        return H.unzip(acc)

    def _inner_product_accumulator(self, b_vector: List[int]) -> List[int]:
        acc = [0]
        for i in range(1, self.size - 3):
            acc.append(acc[i - 1] + b_vector[i - 1] * self.selector_vector[i - 1])
        return acc

    def build(self, kzg: KZG | None = None) -> tuple[Column, Column, Column, Column]:
        b_vec = self._bits_vector()
        acc_x, acc_y = self._conditional_sum_accumulator(b_vec)
        acc_ip = self._inner_product_accumulator(b_vec)

        columns = [
            Column("b", b_vec),
            Column("accx", acc_x),
            Column("accy", acc_y),
            Column("accip", acc_ip),
        ]
        for col in columns:
            col.interpolate(self.omega, self.prime)
            col.commit(kzg)
        return tuple(columns)

    def result(self, Blinding_point):
        """
        input: public key, secret vector and Blinding Base
        output: relation as Result Point
        """
        # sw_H = sw.from_twisted_edwards(Blinding_point)
        sw_H = Blinding_point
        PK_k = self.ring_pk[self.producer_index]
        Result_point = TE.add(PK_k, TE.mul(self.secret_t, sw_H))
        return Result_point

    def result_p_seed(self, result):
        """result plus seed"""
        # res=sw.add(result, sw.from_twisted_edwards(SeedPoint))
        res = TE.add(result, SeedPoint)
        return res
