"""
Arkworks-compatible serialization utilities.

These helpers mirror the formats expected by tests.utils.arkworks_serde
and are intended for exporting Python-generated proofs to arkworks.
"""
from __future__ import annotations

from typing import Any

from py_ecc.bls12_381 import bls12_381_pairing as pairing
from py_ecc.optimized_bls12_381 import FQ
from py_ecc.optimized_bls12_381 import normalize as nm

FIELD_MODULUS = pairing.field_modulus


def _to_int(value: Any) -> int:
    return int(value)


def serialize_fq_field_element(value: int | FQ) -> bytes:
    """Serialize a field element as 32-byte little-endian."""
    return _to_int(value).to_bytes(32, "little")


def _is_zero_fq2(value: Any) -> bool:
    if hasattr(value, "coeffs"):
        c0, c1 = value.coeffs
        return int(c0) == 0 and int(c1) == 0
    if isinstance(value, tuple) and len(value) == 2:
        return int(value[0]) == 0 and int(value[1]) == 0
    return False


def serialize_bls12_381_g1(point: tuple) -> bytes:
    """Serialize a BLS12-381 G1 point in arkworks compressed format."""
    if len(point) == 3:
        # Jacobian
        x, y, z = point
        if int(z) == 0:
            # Point at infinity
            x_bytes = b"\x00" * 48
            flags = 0xC0  # compressed + infinity
            return bytes([x_bytes[0] | flags]) + x_bytes[1:]
        x_aff, y_aff = nm(point)
        x = x_aff
        y = y_aff
    elif len(point) == 2:
        x, y = point
    else:
        raise ValueError("Invalid G1 point format")

    x_int = _to_int(x)
    y_int = _to_int(y)

    x_bytes = bytearray(x_int.to_bytes(48, "big"))
    # Clear top 3 bits before setting flags
    x_bytes[0] &= 0x1F

    flags = 0x80  # compressed
    if y_int > (FIELD_MODULUS - 1) // 2:
        flags |= 0x20  # lexicographically largest

    x_bytes[0] |= flags
    return bytes(x_bytes)


def serialize_bls12_381_g2(point: tuple) -> bytes:
    """Serialize a BLS12-381 G2 point in arkworks compressed format."""
    if len(point) == 3:
        x, y, z = point
        if _is_zero_fq2(z):
            x_bytes = b"\x00" * 48
            flags = 0xC0
            return bytes([x_bytes[0] | flags]) + x_bytes[1:] + b"\x00" * 48
        x_aff, y_aff = nm(point)
        x = x_aff
        y = y_aff
    elif len(point) == 2:
        x, y = point
    else:
        raise ValueError("Invalid G2 point format")

    if hasattr(x, "coeffs"):
        x_c0, x_c1 = x.coeffs
        y_c0, y_c1 = y.coeffs
        x_c0_int = _to_int(x_c0)
        x_c1_int = _to_int(x_c1)
        y_c1_int = _to_int(y_c1)
    elif isinstance(x, tuple) and len(x) == 2:
        # Assume (c0, c1) ordering as used by py_ecc and SRS loader
        x_c0_int = _to_int(x[0])
        x_c1_int = _to_int(x[1])
        y_c1_int = _to_int(y[1])
    else:
        raise ValueError("Unsupported G2 coordinate format")

    x_c1_bytes = bytearray(x_c1_int.to_bytes(48, "big"))
    x_c0_bytes = x_c0_int.to_bytes(48, "big")

    # Clear top 3 bits before setting flags
    x_c1_bytes[0] &= 0x1F

    flags = 0x80  # compressed
    if y_c1_int > (FIELD_MODULUS - 1) // 2:
        flags |= 0x20

    x_c1_bytes[0] |= flags
    return bytes(x_c1_bytes) + x_c0_bytes


def serialize_ring_proof(
    column_commitments: list[tuple],
    columns_at_zeta: list[int],
    quotient_commitment: tuple,
    lin_at_zeta_omega: int,
    agg_at_zeta_proof: tuple,
    lin_at_zeta_omega_proof: tuple,
) -> bytes:
    """Serialize the ring proof in arkworks-compatible order."""
    out = bytearray()
    for c in column_commitments:
        out.extend(serialize_bls12_381_g1(c))
    for v in columns_at_zeta:
        out.extend(serialize_fq_field_element(v))
    out.extend(serialize_bls12_381_g1(quotient_commitment))
    out.extend(serialize_fq_field_element(lin_at_zeta_omega))
    out.extend(serialize_bls12_381_g1(agg_at_zeta_proof))
    out.extend(serialize_bls12_381_g1(lin_at_zeta_omega_proof))
    return bytes(out)
