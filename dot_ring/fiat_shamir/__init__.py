"""
dot_ring.fiat_shamir

Generic transcript/XOF layer used to build non-interactive proofs.
Implementation will follow SHAKE-based design compatible with ark-transcript.
"""

from dot_ring.fiat_shamir.transcript import Transcript  # noqa: E402
from dot_ring.fiat_shamir.serialize import serialize  # noqa: E402
from dot_ring.fiat_shamir.phases import (
    phase1_alphas,
    phase2_eval_point,
    phase3_nu_vector,
)  # noqa: E402

__all__ = [
    "Transcript",
    "serialize",
    "phase1_alphas",
    "phase2_eval_point",
    "phase3_nu_vector",
]