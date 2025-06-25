
from __future__ import annotations

from typing import Optional, Tuple

from sympy import mod_inverse

from dot_ring.ring_proof.constants import (
    S_PRIME as P,
    S_A as A,
    S_B as B,
    SeedPoint as _TE_SEED,
    PaddingPoint as _TE_PADDING,
    Blinding_Base as _TE_BLIND,
)

_mont_a =29978822694968839326280996386011761570173833766074948509196803838190355340952
_mont_b = 25465760566081946422412445027709227188579564747101592991722834452325077642517

print("Mont_A:", _mont_a)
print("Mont_B:", _mont_b)

