from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import cast

from dot_ring.ring_proof.constants import DEFAULT_SIZE, MAX_RING_SIZE, OMEGAS, S_PRIME, Blinding_Base, PaddingPoint, SeedPoint
from dot_ring.ring_proof.curve.bandersnatch import TwistedEdwardCurve as TE
from dot_ring.ring_proof.helpers import Helpers as H
from dot_ring.ring_proof.params import RingProofParams
from dot_ring.ring_proof.pcs.kzg import KZG
from dot_ring.ring_proof.polynomial.interpolation import poly_interpolate_fft

_H_VEC_DEFAULT = json.load(open(os.path.join(os.path.dirname(__file__), "h_vec.json")))
_H_VEC_DEFAULT = [tuple(pt) for pt in _H_VEC_DEFAULT]

Scalar = int
G1Point = tuple


@dataclass(slots=True)
class Column:
    name: str
    evals: list[int]
    coeffs: list[int] | None = None
    commitment: G1Point | None = None
    size: int = DEFAULT_SIZE

    def interpolate(self, domain_omega: int = OMEGAS[DEFAULT_SIZE], prime: int = S_PRIME) -> None:
        """Fill `self.coeffs` from `self.evals` using FFT interpolation."""
        if self.coeffs is None:
            if len(self.evals) > self.size:
                raise ValueError(f"{self.name} evals length {len(self.evals)} exceeds column size {self.size}")
            self.evals += [0] * (self.size - len(self.evals))
            self.coeffs = poly_interpolate_fft(self.evals, domain_omega, prime)

    def commit(self) -> None:
        if self.coeffs is None:
            raise ValueError("call interpolate() first")
        if self.commitment is None:
            self.commitment = KZG.commit(self.coeffs)


@dataclass(slots=True)
class PublicColumnBuilder:
    size: int = DEFAULT_SIZE
    prime: int = S_PRIME
    omega: int = OMEGAS[DEFAULT_SIZE]
    max_ring_size: int = MAX_RING_SIZE
    padding_rows: int = 4

    @classmethod
    def from_params(cls, params: RingProofParams) -> PublicColumnBuilder:
        return cls(
            size=params.domain_size,
            prime=params.prime,
            omega=params.omega,
            max_ring_size=params.max_ring_size,
            padding_rows=params.padding_rows,
        )

    def _pad_ring_with_padding_point(self, pk_ring: list[tuple[int, int]]) -> list[tuple[int, int]]:
        """Pad ring in‑place with the special padding point until size."""
        # padding_sw = sw.from_twisted_edwards(PaddingPoint)
        padding_sw = PaddingPoint
        while len(pk_ring) < self.max_ring_size:
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
        if len(ring_pk) < self.max_ring_size:
            ring_pk = self._pad_ring_with_padding_point(ring_pk)
        if len(ring_pk) > self.size - self.padding_rows:
            raise ValueError(f"ring size {len(ring_pk)} exceeds max supported size {self.size - self.padding_rows}")
        # 1. ensure ring size
        fill_count = self.size - self.padding_rows - len(ring_pk)
        if fill_count > 0:
            if self.size == len(_H_VEC_DEFAULT):
                h_vec = _H_VEC_DEFAULT
            else:
                h_vec = self._h_vector()
            ring_pk.extend(h_vec[:fill_count])
        if self.padding_rows > 0:
            ring_pk.extend([(0, 0)] * self.padding_rows)

        # 2. unzip into x/y vectors
        px, py = H.unzip(ring_pk)

        # 3. selector vector
        sel = [1 if i < self.max_ring_size else 0 for i in range(self.size)]

        # 4. Columns
        col_px = Column("Px", px, size=self.size)
        col_py = Column("Py", py, size=self.size)
        col_s = Column("s", sel, size=self.size)
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
    size: int = DEFAULT_SIZE
    omega: int = OMEGAS[DEFAULT_SIZE]
    prime: int = S_PRIME
    max_ring_size: int = MAX_RING_SIZE
    padding_rows: int = 4

    @classmethod
    def from_params(
        cls,
        ring_pk: list[tuple[int, int]],
        selector_vector: list[int],
        producer_index: int,
        secret_t: int,
        params: RingProofParams,
    ) -> WitnessColumnBuilder:
        return cls(
            ring_pk=ring_pk,
            selector_vector=selector_vector,
            producer_index=producer_index,
            secret_t=secret_t,
            size=params.domain_size,
            omega=params.omega,
            prime=params.prime,
            max_ring_size=params.max_ring_size,
            padding_rows=params.padding_rows,
        )

    def _bits_vector(self) -> list[int]:
        bv = [1 if i == self.producer_index else 0 for i in range(self.max_ring_size)]
        t_bits = bin(self.secret_t)[2:][::-1]
        bv.extend(int(b) for b in t_bits)
        pad_to = self.size - self.padding_rows
        if len(bv) > pad_to:
            raise ValueError(
                "b vector length exceeds available rows: "
                f"{len(bv)} > {pad_to} (ring_size={self.max_ring_size}, "
                f"secret_t_bits={len(t_bits)}, padding_rows={self.padding_rows})"
            )
        while len(bv) < pad_to:
            bv.append(0)
        bv.append(0)  # padding bit
        return bv

    def _conditional_sum_accumulator(self, b_vector: list[int]) -> tuple[list[int], list[int]]:
        seed_sw = SeedPoint

        acc = [seed_sw]
        acc_len = self.size - self.padding_rows + 1
        for i in range(1, acc_len):
            next_pt = acc[i - 1] if b_vector[i - 1] == 0 else cast(tuple[int, int], TE.add(acc[i - 1], self.ring_pk[i - 1]))
            acc.append(next_pt)
        return H.unzip(acc)

    def _inner_product_accumulator(self, b_vector: list[int]) -> list[int]:
        acc = [0]
        acc_len = self.size - self.padding_rows + 1
        for i in range(1, acc_len):
            acc.append(acc[i - 1] + b_vector[i - 1] * self.selector_vector[i - 1])
        return acc

    def build(self) -> tuple[Column, Column, Column, Column]:
        b_vec = self._bits_vector()
        acc_x, acc_y = self._conditional_sum_accumulator(b_vec)
        acc_ip = self._inner_product_accumulator(b_vec)

        columns = [
            Column("b", b_vec, size=self.size),
            Column("accx", acc_x, size=self.size),
            Column("accy", acc_y, size=self.size),
            Column("accip", acc_ip, size=self.size),
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
        Result_point = cast(
            tuple[int, int],
            TE.add(PK_k, cast(tuple[int, int], TE.mul(self.secret_t, sw_H))),
        )
        return Result_point

    def result_p_seed(self, result: tuple[int, int]) -> tuple[int, int]:
        """result plus seed"""
        # res=sw.add(result, sw.from_twisted_edwards(SeedPoint))
        res = cast(tuple[int, int], TE.add(result, SeedPoint))
        return res
