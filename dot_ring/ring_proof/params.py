from __future__ import annotations

from dataclasses import dataclass, field
from functools import lru_cache

from dot_ring.curve.curve import CurveVariant
from dot_ring.curve.point import CurvePoint
from dot_ring.curve.specs.bandersnatch import Bandersnatch
from dot_ring.ring_proof.constants import D_2048, DEFAULT_SIZE, MAX_RING_SIZE, OMEGA_2048, S_PRIME
from dot_ring.ring_proof.pcs.bn254_kzg import BN254KZG
from dot_ring.ring_proof.pcs.kzg import KZG


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
    pcs: object = field(default=KZG, compare=False, hash=False, repr=False)
    test_vectors: bool = False
    cv: CurveVariant = field(default_factory=lambda: Bandersnatch, compare=False, hash=False)

    def __post_init__(self) -> None:
        if self.cv.name == "BabyJubJub":
            if self.prime == S_PRIME:
                object.__setattr__(self, "prime", int(self.cv.curve.PRIME_FIELD))
            if self.base_root == OMEGA_2048 and self.base_root_size == 2048:
                object.__setattr__(self, "base_root", _primitive_root_of_unity(self.base_root_size, int(self.cv.curve.PRIME_FIELD)))
            if self.pcs is KZG:
                object.__setattr__(self, "pcs", BN254KZG)
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
        default_max_ring_size = self.domain_size - self.padding_rows - self.cv.curve.ORDER.bit_length()
        if self.max_ring_size == MAX_RING_SIZE:
            if default_max_ring_size <= 0:
                raise ValueError(
                    "domain_size is too small for the suite scalar bit length: "
                    f"domain_size={self.domain_size}, padding_rows={self.padding_rows}, "
                    f"scalar_bits={self.cv.curve.ORDER.bit_length()}"
                )
            object.__setattr__(self, "max_ring_size", default_max_ring_size)

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

    @property
    def blinding_base(self) -> tuple[int, int]:
        if self.cv.curve.BBx is None or self.cv.curve.BBy is None:
            raise ValueError(f"{self.cv.name} does not define a ring blinding base")
        return self.affine_to_ring_point((int(self.cv.curve.BBx), int(self.cv.curve.BBy)))

    @property
    def seed_point(self) -> tuple[int, int]:
        if self.cv.curve.ACCUMULATOR_BASE_X is None or self.cv.curve.ACCUMULATOR_BASE_Y is None:
            raise ValueError(f"{self.cv.name} does not define a ring accumulator base")
        return self.affine_to_ring_point((int(self.cv.curve.ACCUMULATOR_BASE_X), int(self.cv.curve.ACCUMULATOR_BASE_Y)))

    @property
    def padding_point(self) -> tuple[int, int]:
        if self.cv.curve.PADDING_X is None or self.cv.curve.PADDING_Y is None:
            raise ValueError(f"{self.cv.name} does not define a ring padding point")
        return self.affine_to_ring_point((int(self.cv.curve.PADDING_X), int(self.cv.curve.PADDING_Y)))

    def affine_to_ring_point(self, point: tuple[int, int]) -> tuple[int, int]:
        if self.cv.name == "Bandersnatch_SW":
            return _bandersnatch_sw_to_te(point)
        return point

    def point_to_ring_point(self, point: CurvePoint) -> tuple[int, int]:
        return self.affine_to_ring_point((int(point.x), int(point.y)))

    @property
    def ring_point_cls(self) -> type[CurvePoint]:
        if self.cv.name == "Bandersnatch_SW":
            return Bandersnatch.point
        return self.cv.point

    @property
    def ring_edwards_a(self) -> int:
        if self.cv.name == "Bandersnatch_SW":
            return int(Bandersnatch.curve.EdwardsA)
        return int(self.cv.curve.EdwardsA)

    def add_points(self, point1: tuple[int, int], point2: tuple[int, int]) -> tuple[int, int]:
        p1 = self.ring_point_cls(point1[0], point1[1])
        p2 = self.ring_point_cls(point2[0], point2[1])
        result = p1 + p2
        return int(result.x), int(result.y)

    def mul_point(self, scalar: int, point: tuple[int, int]) -> tuple[int, int]:
        result = self.ring_point_cls(point[0], point[1]) * scalar
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
        # domain_size >= ring_size + padding_rows + scalar bit decomposition
        scalar_bits = cv.curve.ORDER.bit_length()
        min_domain_size = ring_size + padding_rows + scalar_bits

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
            max_ring_size=domain_size - padding_rows - scalar_bits,
            padding_rows=padding_rows,
            prime=prime,
            base_root=base_root,
            base_root_size=base_root_size,
            test_vectors=test_vectors,
            cv=cv,
        )
