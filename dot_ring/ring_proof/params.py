from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from typing import ClassVar

from dot_ring.curve.curve import CurveVariant
from dot_ring.curve.specs.bandersnatch import Bandersnatch
from dot_ring.ring_proof.constants import D_2048, DEFAULT_SIZE, MAX_RING_SIZE, OMEGA_2048, S_PRIME


def _is_power_of_two(n: int) -> bool:
    return n > 0 and (n & (n - 1)) == 0


def _next_power_of_two(n: int) -> int:
    """Find the next power of 2 greater than or equal to n."""
    if n <= 0:
        return 1
    if _is_power_of_two(n):
        return n
    return 1 << (n.bit_length())


def _omega_for_domain(domain_size: int, prime: int = S_PRIME, base_root: int = OMEGA_2048, base_size: int = 2048) -> int:
    if base_size % domain_size != 0:
        raise ValueError(f"Domain size {domain_size} must divide {base_size}")
    return pow(base_root, base_size // domain_size, prime)


@lru_cache(maxsize=32)
def _domain_for_size(
    domain_size: int,
    prime: int = S_PRIME,
    base_root: int = OMEGA_2048,
    base_size: int = 2048,
) -> tuple[int, ...]:
    omega = _omega_for_domain(domain_size, prime, base_root, base_size)
    return tuple(pow(omega, i, prime) for i in range(domain_size))


def _sqrt_mod_prime(n: int, prime: int) -> int:
    """Tonelli-Shanks modular square root for odd primes."""
    if n == 0:
        return 0
    if prime % 4 == 3:
        return pow(n, (prime + 1) // 4, prime)
    # Check n is a quadratic residue
    if pow(n, (prime - 1) // 2, prime) != 1:
        raise ValueError("No square root exists for provided value")

    # Factor prime-1 = q * 2^s with q odd
    q = prime - 1
    s = 0
    while q % 2 == 0:
        s += 1
        q //= 2

    # Find a quadratic non-residue z
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


@lru_cache(maxsize=8)
def _extend_root_to_size(base_root: int, base_size: int, target_size: int, prime: int) -> tuple[int, int]:
    """Extend a root of unity by repeated square roots until reaching target size."""
    root = base_root
    size = base_size
    while size < target_size:
        root = _sqrt_mod_prime(root, prime)
        size *= 2
    return root, size


@dataclass(frozen=True)
class RingProofParams:
    domain_size: int = DEFAULT_SIZE
    max_ring_size: int = MAX_RING_SIZE
    padding_rows: int = 4
    radix_domain_size: int | None = None
    prime: int = S_PRIME
    base_root: int = OMEGA_2048
    base_root_size: int = 2048
    cv: ClassVar[CurveVariant] = Bandersnatch

    def __post_init__(self) -> None:
        radix_domain_size = self.radix_domain_size
        if radix_domain_size is None:
            radix_domain_size = self.domain_size * 4
            object.__setattr__(self, "radix_domain_size", radix_domain_size)
        if not _is_power_of_two(self.domain_size):
            raise ValueError(f"domain_size must be a power of two, got {self.domain_size}")
        if not _is_power_of_two(radix_domain_size):
            raise ValueError(f"radix_domain_size must be a power of two, got {radix_domain_size}")
        if radix_domain_size % self.domain_size != 0:
            raise ValueError(f"domain_size {self.domain_size} must divide radix_domain_size {radix_domain_size}")
        if radix_domain_size > self.base_root_size:
            root, size = _extend_root_to_size(self.base_root, self.base_root_size, radix_domain_size, self.prime)
            object.__setattr__(self, "base_root", root)
            object.__setattr__(self, "base_root_size", size)
        if self.base_root_size % radix_domain_size != 0:
            raise ValueError(f"radix_domain_size {radix_domain_size} must divide base_root_size {self.base_root_size}")
        if self.padding_rows < 1:
            raise ValueError("padding_rows must be >= 1 to preserve accumulator structure")
        if self.padding_rows >= self.domain_size:
            raise ValueError("padding_rows must be less than domain_size")
        if self.max_ring_size > self.domain_size - self.padding_rows:
            raise ValueError(f"max_ring_size {self.max_ring_size} exceeds supported size {self.domain_size - self.padding_rows}")

    @property
    def omega(self) -> int:
        return _omega_for_domain(self.domain_size, self.prime, self.base_root, self.base_root_size)

    @property
    def domain(self) -> list[int]:
        return list(_domain_for_size(self.domain_size, self.prime, self.base_root, self.base_root_size))

    @property
    def radix_omega(self) -> int:
        return _omega_for_domain(self.radix_domain_size, self.prime, self.base_root, self.base_root_size)

    @property
    def radix_domain(self) -> list[int]:
        if self.radix_domain_size == 2048 and self.base_root_size == 2048 and self.base_root == OMEGA_2048:
            return list(D_2048)
        return list(_domain_for_size(self.radix_domain_size, self.prime, self.base_root, self.base_root_size))

    @property
    def radix_shift(self) -> int:
        return self.radix_domain_size // self.domain_size

    @property
    def last_index(self) -> int:
        return self.domain_size - self.padding_rows

    @property
    def max_effective_ring_size(self) -> int:
        return self.domain_size - self.padding_rows

    @classmethod
    def from_ring_size(
        cls,
        ring_size: int,
        padding_rows: int = 4,
        prime: int = S_PRIME,
        base_root: int = OMEGA_2048,
        base_root_size: int = 2048,
    ) -> RingProofParams:
        """
        Automatically construct RingProofParams based on ring size.

        Calculates the minimum domain size needed to accommodate the ring
        and constructs appropriate parameters.

        Args:
            ring_size: Number of members in the ring
            padding_rows: Number of padding rows (default: 4)
            prime: Field prime (default: S_PRIME)
            base_root: Base root of unity (default: OMEGA_2048)
            base_root_size: Base root size (default: 2048)

        Returns:
            RingProofParams configured for the given ring size
        """
        if ring_size <= 0:
            raise ValueError(f"ring_size must be positive, got {ring_size}")

        # Calculate minimum domain size needed:
        # domain_size >= ring_size + padding_rows
        min_domain_size = ring_size + padding_rows

        # Round up to next power of 2
        domain_size = _next_power_of_two(min_domain_size)

        # Ensure domain_size is reasonable (between 16 and 8192)
        if domain_size < 16:
            domain_size = 16
        elif domain_size > 8192:
            raise ValueError(
                f"Ring size {ring_size} requires domain size {domain_size}, "
                f"which exceeds maximum supported size of 8192. "
                f"Maximum ring size is {8192 - padding_rows}."
            )

        return cls(
            domain_size=domain_size,
            max_ring_size=ring_size,
            padding_rows=padding_rows,
            prime=prime,
            base_root=base_root,
            base_root_size=base_root_size,
        )
