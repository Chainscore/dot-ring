from __future__ import annotations

from dataclasses import dataclass, field
from functools import lru_cache

from dot_ring.curve.curve import CurveVariant
from dot_ring.curve.point import CurvePoint
from dot_ring.curve.specs.bandersnatch import Bandersnatch
from dot_ring.ring_proof.constants import (
    D_2048,
    DEFAULT_SIZE,
    EVAL_DOMAINS,
    MAX_RING_SIZE,
    OMEGA_2048,
    OMEGAS,
    S_PRIME,
    ZK_ROWS,
)
from dot_ring.ring_proof.pcs.kzg import KZG
from dot_ring.ring_proof.pcs.protocol import PCS

# 2047-member rings need a 4096-row PIOP domain and a 16384-point radix
# domain. KZG grows its SRS lazily when these larger quotient polynomials are
# requested.
MAX_PIOP_DOMAIN_SIZE = 4096


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
    if _uses_precomputed_bls_domain(prime, base_root, base_size) and domain_size in OMEGAS:
        return OMEGAS[domain_size]
    return pow(base_root, base_size // domain_size, prime)


def _uses_precomputed_bls_domain(prime: int, base_root: int, base_size: int) -> bool:
    return prime == S_PRIME and base_root == OMEGA_2048 and base_size == 2048


# Global bounded cache: roots are deterministic for one size/field pair.
@lru_cache(maxsize=16)
def _primitive_root_of_unity(size: int, prime: int) -> int:
    if not _is_power_of_two(size):
        raise ValueError(f"root size must be a power of two, got {size}")
    if (prime - 1) % size != 0:
        raise ValueError(f"root size {size} does not divide prime - 1")
    exponent = (prime - 1) // size
    candidate = 2
    while True:
        root = pow(candidate, exponent, prime)
        if root != 1 and pow(root, size, prime) == 1 and pow(root, size // 2, prime) != 1:
            return root
        candidate += 1


# Global bounded cache: evaluation domains are reused across roots/proofs.
@lru_cache(maxsize=32)
def _domain_for_size(
    domain_size: int,
    prime: int = S_PRIME,
    base_root: int = OMEGA_2048,
    base_size: int = 2048,
) -> tuple[int, ...]:
    if _uses_precomputed_bls_domain(prime, base_root, base_size) and domain_size in EVAL_DOMAINS:
        return tuple(EVAL_DOMAINS[domain_size])
    omega = _omega_for_domain(domain_size, prime, base_root, base_size)
    domain = [1] * domain_size
    current = 1
    for i in range(domain_size):
        domain[i] = current
        current = (current * omega) % prime
    return tuple(domain)


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


_BANDERSNATCH_MONT_A_OVER_THREE = 9992940898322946442093665462003920523391277922024982836398934612730118446984
_BANDERSNATCH_MONT_B = 25465760566081946422412445027709227188579564747101592991722834452325077642517


def _bandersnatch_sw_to_te(point: tuple[int, int]) -> tuple[int, int]:
    prime = S_PRIME
    sw_x, sw_y = point
    mont_x = (_BANDERSNATCH_MONT_B * sw_x - _BANDERSNATCH_MONT_A_OVER_THREE) % prime
    mont_y = (_BANDERSNATCH_MONT_B * sw_y) % prime
    v = mont_x * pow(mont_y, -1, prime)
    w = (mont_x - 1) * pow((mont_x + 1) % prime, -1, prime)
    return v % prime, w % prime


# Global bounded cache: extended roots are deterministic for one target size.
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
    pcs: type[PCS] = field(default=KZG, compare=False, hash=False, repr=False)
    test_vectors: bool = False
    cv: CurveVariant = field(default_factory=lambda: Bandersnatch, compare=False, hash=False)

    @property
    def scalar_bits(self) -> int:
        return self.cv.curve.params.subgroup_order.bit_length()

    @property
    def row_overhead(self) -> int:
        return self.scalar_bits + self.padding_rows

    def __post_init__(self) -> None:
        if self.cv.name == "BabyJubJub":
            raise ValueError("BabyJubJub ring proofs are not supported; use Tiny/Thin/Pedersen VRFs for that curve")
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
        if self.domain_size > MAX_PIOP_DOMAIN_SIZE:
            raise ValueError(f"domain_size {self.domain_size} exceeds supported SRS domain size {MAX_PIOP_DOMAIN_SIZE}")
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
        if self.padding_rows != ZK_ROWS + 1:
            raise ValueError(f"padding_rows must be {ZK_ROWS + 1} to match the {ZK_ROWS} hidden rows")
        max_supported = self.domain_size - self.row_overhead
        if max_supported <= 0:
            raise ValueError(
                "domain_size is too small for the scalar bit decomposition: "
                f"domain_size={self.domain_size}, scalar_bits={self.scalar_bits}, padding_rows={self.padding_rows}"
            )
        if self.max_ring_size == MAX_RING_SIZE and max_supported != MAX_RING_SIZE:
            object.__setattr__(self, "max_ring_size", max_supported)
        elif self.max_ring_size > max_supported:
            raise ValueError(f"max_ring_size {self.max_ring_size} exceeds supported size {max_supported}")
        ensure_srs_size = getattr(self.pcs, "ensure_srs_size", None)
        if ensure_srs_size is not None:
            ensure_srs_size(self.required_srs_degree)

    @property
    def omega(self) -> int:
        return _omega_for_domain(self.domain_size, self.prime, self.base_root, self.base_root_size)

    @property
    def domain(self) -> list[int]:
        return list(_domain_for_size(self.domain_size, self.prime, self.base_root, self.base_root_size))

    @property
    def radix_omega(self) -> int:
        return _omega_for_domain(self._radix_domain_size, self.prime, self.base_root, self.base_root_size)

    @property
    def radix_domain(self) -> list[int]:
        radix_domain_size = self._radix_domain_size
        if radix_domain_size == 2048 and self.base_root_size == 2048 and self.base_root == OMEGA_2048:
            return list(D_2048)
        return list(_domain_for_size(radix_domain_size, self.prime, self.base_root, self.base_root_size))

    @property
    def radix_shift(self) -> int:
        return self._radix_domain_size // self.domain_size

    @property
    def _radix_domain_size(self) -> int:
        if self.radix_domain_size is None:
            raise ValueError("radix_domain_size is not initialized")
        return self.radix_domain_size

    @property
    def last_index(self) -> int:
        return self.domain_size - self.padding_rows

    @property
    def max_effective_ring_size(self) -> int:
        return self.domain_size - self.row_overhead

    @property
    def required_srs_degree(self) -> int:
        return max(self.domain_size - 1, self._radix_domain_size - self.domain_size)

    @property
    def blinding_base(self) -> tuple[int, int]:
        base = self.cv.curve.params.auxiliary_points.blinding_base
        if base is None:
            raise ValueError(f"{self.cv.name} does not define a ring blinding base")
        return self.affine_to_ring_point((int(base[0]), int(base[1])))

    @property
    def seed_point(self) -> tuple[int, int]:
        base = self.cv.curve.params.auxiliary_points.accumulator_base
        if base is None:
            raise ValueError(f"{self.cv.name} does not define a ring accumulator base")
        return self.affine_to_ring_point((int(base[0]), int(base[1])))

    @property
    def padding_point(self) -> tuple[int, int]:
        point = self.cv.curve.params.auxiliary_points.padding_point
        if point is None:
            raise ValueError(f"{self.cv.name} does not define a ring padding point")
        return self.affine_to_ring_point((int(point[0]), int(point[1])))

    def affine_to_ring_point(self, point: tuple[int, int]) -> tuple[int, int]:
        if self.cv.name == "Bandersnatch_SW":
            return _bandersnatch_sw_to_te(point)
        return point

    def point_to_ring_point(self, point: CurvePoint) -> tuple[int, int]:
        return self.affine_to_ring_point((int(point.x), int(point.y)))

    def ring_curve_variant(self) -> CurveVariant:
        if self.cv.name == "Bandersnatch_SW":
            return Bandersnatch
        return self.cv

    def ring_point(self, point: tuple[int, int]) -> CurvePoint:
        return self.ring_curve_variant().point(point[0], point[1])

    @property
    def ring_edwards_a(self) -> int:
        if self.cv.name == "Bandersnatch_SW":
            return int(Bandersnatch.curve.params.a)
        return int(self.cv.curve.params.a)

    @property
    def ring_edwards_d(self) -> int:
        if self.cv.name == "Bandersnatch_SW":
            return int(Bandersnatch.curve.params.d)
        return int(self.cv.curve.params.d)

    def add_points(self, point1: tuple[int, int], point2: tuple[int, int]) -> tuple[int, int]:
        p1 = self.ring_point(point1)
        p2 = self.ring_point(point2)
        result = p1 + p2
        return int(result.x), int(result.y)

    def mul_point(self, scalar: int, point: tuple[int, int]) -> tuple[int, int]:
        result = self.ring_point(point) * scalar
        return int(result.x), int(result.y)

    @classmethod
    def from_ring_size(
        cls,
        ring_size: int,
        padding_rows: int = 4,
        prime: int = S_PRIME,
        base_root: int = OMEGA_2048,
        base_root_size: int = 2048,
        test_vectors: bool = False,
        cv: CurveVariant = Bandersnatch,
    ) -> RingProofParams:
        """
        Automatically construct RingProofParams based on ring size.

        The ring proof table needs one row per ring member, one row per scalar
        bit in the producer index decomposition, and the fixed padding rows.
        The returned max_ring_size is the full capacity for the selected
        power-of-two domain, matching the ark-vrf sizing rule.

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
        scalar_bits = cv.curve.params.subgroup_order.bit_length()
        overhead = scalar_bits + padding_rows
        domain_size = _next_power_of_two(ring_size + overhead)
        max_ring_size = domain_size - overhead

        return cls(
            domain_size=domain_size,
            max_ring_size=max_ring_size,
            padding_rows=padding_rows,
            prime=prime,
            base_root=base_root,
            base_root_size=base_root_size,
            test_vectors=test_vectors,
            cv=cv,
        )
