from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import cast

from dot_ring.ring_proof.constants import (
    MAX_RING_SIZE,
    OMEGA,
    S_PRIME,
    SIZE,
    Blinding_Base,
    PaddingPoint,
    SeedPoint,
)
from dot_ring.ring_proof.curve.bandersnatch import TwistedEdwardCurve as TE
from dot_ring.ring_proof.helpers import Helpers as H
from dot_ring.ring_proof.pcs.kzg import KZG
from dot_ring.ring_proof.polynomial.interpolation import poly_interpolate_fft

h_vec = json.load(open(os.path.join(os.path.dirname(__file__), "h_vec.json")))

Scalar = int
G1Point = tuple


@dataclass(slots=True)
class Column:
    name: str
    evals: list[int]
    coeffs: list[int] | None = None
    commitment: G1Point | None = None
    size: int = SIZE

    def interpolate(self, domain_omega: int = OMEGA, prime: int = S_PRIME) -> None:
        """Fill `self.coeffs` from `self.evals` using FFT interpolation."""
        if self.coeffs is None:
            self.evals += [0] * (SIZE - len(self.evals))
            self.coeffs = poly_interpolate_fft(self.evals, domain_omega, prime)

    def commit(self) -> None:
        if self.coeffs is None:
            raise ValueError("call interpolate() first")
        if self.commitment is None:
            self.commitment = KZG.commit(self.coeffs)


@dataclass(slots=True)
class PublicColumnBuilder:
    size: int = SIZE
    prime: int = S_PRIME
    omega: int = OMEGA

    def _pad_ring_with_padding_point(
        self, pk_ring: list[tuple[int, int]], size: int = MAX_RING_SIZE
    ) -> list[tuple[int, int]]:
        """Pad ring in‑place with the special padding point until size."""
        # padding_sw = sw.from_twisted_edwards(PaddingPoint)
        padding_sw = PaddingPoint
        while len(pk_ring) < MAX_RING_SIZE:
            pk_ring.append(padding_sw)
        return pk_ring

    def _h_vector(self, blinding_base: tuple[int, int] = Blinding_Base) -> list[tuple[int, int]]:
        """Return `[2⁰·H, 2¹·H, …]` in short‑Weierstrass coords."""
        # sw_bb = sw.from_twisted_edwards(blinding_base)
        sw_bb = blinding_base
        # print("Blinding Base:",sw_bb)
        res = [cast(tuple[int, int], TE.mul(pow(2, i, S_PRIME), sw_bb)) for i in range(self.size)]
        return res  # B_Neck

    def build(self, ring_pk: list[tuple[int, int]]) -> tuple[Column, Column, Column]:
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
            col.commit()
        return col_px, col_py, col_s


@dataclass(slots=True)
class WitnessColumnBuilder:
    ring_pk: list[tuple[int, int]]
    selector_vector: list[int]
    producer_index: int
    secret_t: int
    size: int = SIZE
    omega: int = OMEGA
    prime: int = S_PRIME

    def _bits_vector(self) -> list[int]:
        bv = [1 if i == self.producer_index else 0 for i in range(MAX_RING_SIZE)]
        t_bits = bin(self.secret_t)[2:][::-1]
        bv.extend(int(b) for b in t_bits)
        while len(bv) < self.size - 4:
            bv.append(0)
        bv.append(0)  # padding bit
        return bv

    def _conditional_sum_accumulator(self, b_vector: list[int]) -> tuple[list[int], list[int]]:
        seed_sw = SeedPoint

        acc = [seed_sw]
        for i in range(1, self.size - 3):
            next_pt = acc[i - 1] if b_vector[i - 1] == 0 else cast(tuple[int, int], TE.add(acc[i - 1], self.ring_pk[i - 1]))
            acc.append(next_pt)
        return H.unzip(acc)

    def _inner_product_accumulator(self, b_vector: list[int]) -> list[int]:
        acc = [0]
        for i in range(1, self.size - 3):
            acc.append(acc[i - 1] + b_vector[i - 1] * self.selector_vector[i - 1])
        return acc

    def build(self) -> tuple[Column, Column, Column, Column]:
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
            col.commit()
        return (columns[0], columns[1], columns[2], columns[3])

    def result(self, Blinding_point: tuple[int, int]) -> tuple[int, int]:
        """
        input: public key, secret vector and Blinding Base
        output: relation as Result Point
        """
        # sw_H = sw.from_twisted_edwards(Blinding_point)
        sw_H = Blinding_point
        PK_k = self.ring_pk[self.producer_index]
        Result_point = cast(tuple[int, int], TE.add(PK_k, cast(tuple[int, int], TE.mul(self.secret_t, sw_H))))
        return Result_point

    def result_p_seed(self, result: tuple[int, int]) -> tuple[int, int]:
        """result plus seed"""
        # res=sw.add(result, sw.from_twisted_edwards(SeedPoint))
        res = cast(tuple[int, int], TE.add(result, SeedPoint))
        return res
