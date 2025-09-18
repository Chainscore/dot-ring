#
# from __future__ import annotations
#
# from typing import Optional, Tuple
#
# from sympy import mod_inverse
#
# from dot_ring.ring_proof.constants import (
#     S_PRIME as P,
#     S_A as A,
#     S_B as B,
#     SeedPoint as _TE_SEED,
#     PaddingPoint as _TE_PADDING,
#     Blinding_Base as _TE_BLIND,
# )
#
# _mont_a =29978822694968839326280996386011761570173833766074948509196803838190355340952
# _mont_b = 25465760566081946422412445027709227188579564747101592991722834452325077642517
#
#
# class ShortWeierstrassCurve:
#     """Encapsulates the Bandersnatch curve in short‑Weierstrass form."""
#
#     # Public constants
#     P: int = P  # Field prime
#     A: int = A
#     B: int = B
#
#     # Optionally expose a canonical generator in WS form; converting from TE
#     SEED_POINT: Tuple[int, int] = None  # will be set at import‑time
#     PADDING_POINT: Tuple[int, int] = None
#     BLINDING_POINT: Tuple[int, int] = None
#
#     @staticmethod
#     def _mod_inv(x: int) -> int:
#         """Modular inverse helper (positive representative)."""
#         return mod_inverse(x % ShortWeierstrassCurve.P, ShortWeierstrassCurve.P)
#
#     @classmethod
#     def is_on_curve(cls, pt: Tuple[int, int]) -> bool:
#         x, y = pt
#         return (y * y - (x * x * x + cls.A * x + cls.B)) % cls.P == 0
#
#
#     @classmethod
#     def add(cls, P1: Optional[Tuple[int, int]], P2: Optional[Tuple[int, int]]):
#         """Affine point addition; `None` encodes the point at infinity."""
#         if P1 is None:
#             return P2
#         if P2 is None:
#             return P1
#         x1, y1 = P1
#         x2, y2 = P2
#         if x1 == x2 and y1 == (-y2 % cls.P):
#             return None  # P + (−P) = O
#         if P1 == P2:
#             return cls.double(P1)
#         lam = (y2 - y1) * cls._mod_inv(x2 - x1)
#         x3 = (lam * lam - x1 - x2) % cls.P
#         y3 = (lam * (x1 - x3) - y1) % cls.P
#         return (x3, y3)
#
#     @classmethod
#     def double(cls, P: Tuple[int, int]):
#         x1, y1 = P
#         lam = (3 * x1 * x1 + cls.A) * cls._mod_inv(2 * y1)
#         x3 = (lam * lam - 2 * x1) % cls.P
#         y3 = (lam * (x1 - x3) - y1) % cls.P
#         return (x3, y3)
#
#     @classmethod
#     def sub(cls, P1, P2):
#         """P1 − P2."""
#         if P2 is None:
#             return P1
#         x2, y2 = P2
#         return cls.add(P1, (x2, (-y2) % cls.P))
#
#     @classmethod
#     def mul(cls, k: int, P: Tuple[int, int]):
#         """Simple double‑and‑add scalar multiplication (constant‑time not yet!)."""
#         result = None
#         addend = P
#         while k:
#             if k & 1:
#                 result = cls.add(result, addend)
#             addend = cls.double(addend)
#             k >>= 1
#         return result
#
#
#     @staticmethod
#     def _edwards_to_mont(pt: Tuple[int, int]):
#         x, y = pt
#         u = (1 + y) * ShortWeierstrassCurve._mod_inv(1 - y) % P
#         v = (1 + y) * ShortWeierstrassCurve._mod_inv(x - x * y) % P
#         return (u, v)
#
#     @staticmethod
#     def _mont_to_ws(pt: Tuple[int, int]):
#         u, v = pt
#         x = (u + _mont_a * ShortWeierstrassCurve._mod_inv(3)) * ShortWeierstrassCurve._mod_inv(_mont_b) % P
#         y = v * ShortWeierstrassCurve._mod_inv(_mont_b) % P
#         return (x, y)
#
#     @classmethod
#     def from_twisted_edwards(cls, pt: Tuple[int, int]):
#         return cls._mont_to_ws(cls._edwards_to_mont(pt))
#
#     @staticmethod
#     def _ws_to_mont(pt: Tuple[int, int]):
#         x_ws, y_ws = pt
#         u = (_mont_b * x_ws - _mont_a * ShortWeierstrassCurve._mod_inv(3)) % P
#         v = _mont_b * y_ws % P
#         return (u, v)
#
#     @staticmethod
#     def _mont_to_edwards(pt: Tuple[int, int]):
#         u, v = pt
#         x_te = u * ShortWeierstrassCurve._mod_inv(v) % P
#         y_te = (u - 1) * ShortWeierstrassCurve._mod_inv(u + 1) % P
#         return (x_te, y_te)
#
#     @classmethod
#     def to_twisted_edwards(cls, pt: Tuple[int, int]):
#         return cls._mont_to_edwards(cls._ws_to_mont(pt))
#
#
#     @staticmethod
#     def _mod_sqrt(a: int) -> int:
#         """Tonelli–Shanks.  Raises if `a` is not a quadratic residue."""
#         p = P
#         if pow(a, (p - 1) >> 1, p) != 1:
#             raise ValueError("no sqrt")
#         if p & 3 == 3:
#             return pow(a, (p + 1) >> 2, p)
#         # Tonelli–Shanks general case (rarely hit for BN‑field primes)
#         q, s = p - 1, 0
#         while q & 1 == 0:
#             q >>= 1; s += 1
#         z = 2
#         while pow(z, (p - 1) >> 1, p) != p - 1:
#             z += 1
#         c = pow(z, q, p)
#         r = pow(a, (q + 1) >> 1, p)
#         t = pow(a, q, p)
#         m = s
#         while t != 1:
#             i, tmp = 1, pow(t, 2, p)
#             while tmp != 1:
#                 tmp = pow(tmp, 2, p); i += 1
#             b = pow(c, 1 << (m - i - 1), p)
#             r = r * b % p
#             c = pow(b, 2, p)
#             t = t * c % p
#             m = i
#         return r
#
#     @classmethod
#     def compress(cls, pt: Tuple[int, int]) -> bytes:
#         x, y = pt
#         prefix = 0x02 if y % 2 == 0 else 0x03
#         byte_len = (cls.P.bit_length() + 7) // 8
#         return bytes([prefix]) + x.to_bytes(byte_len, "big")
#
#     @classmethod
#     def decompress(cls, data: bytes) -> Tuple[int, int]:
#         prefix, x_bytes = data[0], data[1:]
#         x = int.from_bytes(x_bytes, "big")
#         rhs = (pow(x, 3, cls.P) + cls.A * x + cls.B) % cls.P
#         y = cls._mod_sqrt(rhs)
#         if (y & 1) ^ (prefix & 1):
#             y = cls.P - y  # choose the sign according to prefix
#         pt = (x, y)
#         if not cls.is_on_curve(pt):
#             raise ValueError("invalid compressed point")
#         return pt
#
# __all__ = [
#     "ShortWeierstrassCurve",
# ]
