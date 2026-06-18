from __future__ import annotations

import json
import os
import secrets
from collections.abc import Sequence
from dataclasses import dataclass
from typing import cast

from dot_ring.ring_proof.constants import DEFAULT_SIZE, MAX_RING_SIZE, OMEGAS, S_PRIME, ZK_ROWS, SeedPoint
from dot_ring.ring_proof.helpers import Helpers as H
from dot_ring.ring_proof.params import RingProofParams
from dot_ring.ring_proof.pcs.kzg import KZG
from dot_ring.ring_proof.pcs.protocol import PCS, G1Commitment
from dot_ring.ring_proof.polynomial.interpolation import poly_interpolate_fft

_H_VEC_DEFAULT = json.load(open(os.path.join(os.path.dirname(__file__), "h_vec.json")))
_H_VEC_DEFAULT = [tuple(pt) for pt in _H_VEC_DEFAULT]

Scalar = int


@dataclass(slots=True)
class Column:
    name: str
    evals: list[int]
    coeffs: list[int] | None = None
    commitment: G1Commitment | None = None
    size: int = DEFAULT_SIZE

    def interpolate(
        self,
        domain_omega: int = OMEGAS[DEFAULT_SIZE],
        prime: int = S_PRIME,
        hidden: bool = False,
        test_vectors: bool = False,
    ) -> None:
        """Fill `self.coeffs` from `self.evals` using FFT interpolation.

        When ``hidden=True`` and ``test_vectors=False``, the last
        ``ZK_ROWS`` positions are filled with cryptographically random
        field elements (random blinding) to preserve zero-knowledge.
        """
        if self.coeffs is None:
            if hidden and not test_vectors:
                capacity = self.size - ZK_ROWS
                if len(self.evals) > capacity:
                    raise ValueError(f"{self.name} evals length {len(self.evals)} exceeds capacity {capacity} (size={self.size}, ZK_ROWS={ZK_ROWS})")
                self.evals += [0] * (capacity - len(self.evals))
                self.evals += [secrets.randbelow(prime) for _ in range(ZK_ROWS)]
            else:
                if len(self.evals) > self.size:
                    raise ValueError(f"{self.name} evals length {len(self.evals)} exceeds column size {self.size}")
                self.evals += [0] * (self.size - len(self.evals))
            self.coeffs = poly_interpolate_fft(self.evals, domain_omega, prime)

    def commit(self, pcs: type[PCS] = KZG) -> None:
        if self.coeffs is None:
            raise ValueError("call interpolate() first")
        if self.commitment is None:
            self.commitment = pcs.commit(self.coeffs)


def require_commitment(column: Column) -> G1Commitment:
    if column.commitment is None:
        raise ValueError(f"{column.name} commitment is missing")
    return column.commitment


@dataclass(slots=True)
class WitnessColumnBuilder:
    ring_pk: Sequence[tuple[int, int]]
    selector_vector: list[int]
    producer_index: int
    secret_t: int
    size: int = DEFAULT_SIZE
    omega: int = OMEGAS[DEFAULT_SIZE]
    prime: int = S_PRIME
    max_ring_size: int = MAX_RING_SIZE
    padding_rows: int = 4
    test_vectors: bool = False
    seed_point: tuple[int, int] = SeedPoint
    params: RingProofParams | None = None
    pcs: type[PCS] = KZG

    @classmethod
    def from_params(
        cls,
        ring_pk: Sequence[tuple[int, int]],
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
            test_vectors=params.test_vectors,
            seed_point=params.seed_point,
            params=params,
            pcs=params.pcs,
        )

    def _add(self, point1: tuple[int, int], point2: tuple[int, int]) -> tuple[int, int]:
        if self.params is None:
            raise ValueError("Ring proof params are required for point arithmetic")
        result = self.params.add_points(point1, point2)
        return result

    def _mul(self, scalar: int, point: tuple[int, int]) -> tuple[int, int]:
        if self.params is None:
            raise ValueError("Ring proof params are required for point arithmetic")
        result = self.params.mul_point(scalar, point)
        return result

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
        seed_sw = self.seed_point

        acc = [seed_sw]
        acc_len = self.size - self.padding_rows + 1
        for i in range(1, acc_len):
            next_pt = acc[i - 1] if b_vector[i - 1] == 0 else self._add(acc[i - 1], self.ring_pk[i - 1])
            acc.append(next_pt)
        return cast(tuple[list[int], list[int]], H.unzip(acc))

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
            col.interpolate(self.omega, self.prime, hidden=True, test_vectors=self.test_vectors)
            col.commit(self.pcs)
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
            self._add(PK_k, self._mul(self.secret_t, sw_H)),
        )
        return Result_point

    def result_p_seed(self, result: tuple[int, int]) -> tuple[int, int]:
        """result plus seed"""
        # res=sw.add(result, sw.from_twisted_edwards(SeedPoint))
        res = cast(tuple[int, int], self._add(result, self.seed_point))
        return res
