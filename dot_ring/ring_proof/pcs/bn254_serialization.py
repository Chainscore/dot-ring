from __future__ import annotations

import py_ecc.optimized_bn128 as bn254  # type: ignore[import-untyped]


def sqrt_mod_prime(n: int, prime: int) -> int:
    if n == 0:
        return 0
    if pow(n, (prime - 1) // 2, prime) != 1:
        raise ValueError("point is not on BN254 G1")
    if prime % 4 == 3:
        return pow(n, (prime + 1) // 4, prime)
    q = prime - 1
    s = 0
    while q % 2 == 0:
        s += 1
        q //= 2
    z = 2
    while pow(z, (prime - 1) // 2, prime) != prime - 1:
        z += 1
    m = s
    c = pow(z, q, prime)
    x = pow(n, (q + 1) // 2, prime)
    t = pow(n, q, prime)
    while t != 1:
        i = 1
        t2i = (t * t) % prime
        while i < m:
            if t2i == 1:
                break
            t2i = (t2i * t2i) % prime
            i += 1
        b = pow(c, 1 << (m - i - 1), prime)
        x = (x * b) % prime
        t = (t * b * b) % prime
        c = (b * b) % prime
        m = i
    return x


def read_field(data: bytes, *, flags: bool = False) -> tuple[int, int]:
    if len(data) != 32:
        raise ValueError(f"invalid BN254 field length: expected 32, got {len(data)}")
    masked = bytearray(data)
    flag = 0
    if flags:
        flag = masked[-1] & 0xC0
        masked[-1] &= 0x3F
        if flag == 0xC0:
            raise ValueError("invalid BN254 point flags")
    value = int.from_bytes(masked, "little")
    if value >= bn254.field_modulus:
        raise ValueError("invalid BN254 field element")
    return value, flag


def write_field(value: int, flag: int = 0) -> bytes:
    if value < 0 or value >= bn254.field_modulus:
        raise ValueError("invalid BN254 field element")
    if flag not in (0, 0x40, 0x80):
        raise ValueError("invalid BN254 point flags")
    data = bytearray(value.to_bytes(32, "little"))
    if data[-1] & 0xC0:
        raise ValueError("BN254 field element overlaps point flags")
    data[-1] |= flag
    return bytes(data)


def y_flag(y: int) -> int:
    return 0 if y <= (-y % bn254.field_modulus) else 0x80
