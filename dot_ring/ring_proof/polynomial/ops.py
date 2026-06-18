from collections.abc import Sequence
from functools import lru_cache

from dot_ring.ring_proof.polynomial.fft import evaluate_poly_fft, inverse_fft

_ROOT_SEARCH_START = 5


def _is_power_of_two(n: int) -> bool:
    return n > 0 and (n & (n - 1)) == 0


def _root_of_unity_domain_omega(domain: Sequence[int], prime: int) -> int | None:
    n = len(domain)
    if not _is_power_of_two(n):
        return None
    if domain[0] % prime != 1:
        return None
    if n == 1:
        return 1

    omega = domain[1] % prime
    if omega == 1 or pow(omega, n, prime) != 1 or pow(omega, n // 2, prime) == 1:
        return None

    current = 1
    for x in domain:
        if x % prime != current:
            return None
        current = (current * omega) % prime
    return omega


@lru_cache(maxsize=128)
def get_root_of_unity(n: int, prime: int) -> int:
    """Return an n-th primitive root of unity in the given prime field."""
    if not _is_power_of_two(n):
        raise ValueError(f"n must be a power of two, got {n}")
    if (prime - 1) % n != 0:
        raise ValueError(f"n={n} does not divide prime-1")

    exponent = (prime - 1) // n
    candidate = _ROOT_SEARCH_START
    while True:
        root = pow(candidate, exponent, prime)
        if root != 1 and pow(root, n, prime) == 1 and (n == 1 or pow(root, n // 2, prime) != 1):
            return root
        candidate += 1


def poly_add(poly1: Sequence[int], poly2: Sequence[int], prime: int) -> list[int]:
    """Add two polynomials in a prime field."""
    result_len = max(len(poly1), len(poly2))
    result = [0] * result_len

    for i in range(len(poly1)):
        result[i] = poly1[i]

    for i in range(len(poly2)):
        val = result[i] + poly2[i]
        if val >= prime:
            val -= prime
        result[i] = val

    return result


def poly_scalar_mul(poly: Sequence[int], scalar: int, prime: int) -> list[int]:
    """Multiply a polynomial by a scalar in a prime field."""
    n = len(poly)

    if scalar >= prime:
        scalar = scalar % prime

    if scalar == 0:
        return [0] * n
    if scalar == 1:
        return [coef % prime if coef >= prime else coef for coef in poly]

    result = [0] * n
    for i, coef in enumerate(poly):
        if coef >= prime:
            coef = coef % prime
        result[i] = (coef * scalar) % prime

    return result


def poly_mul_linear(poly: Sequence[int], a: int, b: int, prime: int) -> list[int]:
    """Multiply a polynomial by (a*x + b) in O(n)."""
    n = len(poly)
    result = [0] * (n + 1)

    if a >= prime:
        a = a % prime
    if b >= prime:
        b = b % prime

    coef = poly[0]
    if coef >= prime:
        coef = coef % prime
    result[0] = (b * coef) % prime

    for i in range(1, n):
        prev_coef = poly[i - 1]
        if prev_coef >= prime:
            prev_coef = prev_coef % prime

        coef = poly[i]
        if coef >= prime:
            coef = coef % prime

        term1 = (a * prev_coef) % prime
        term2 = (b * coef) % prime
        result[i] = (term1 + term2) % prime

    coef = poly[n - 1]
    if coef >= prime:
        coef = coef % prime
    result[n] = (a * coef) % prime

    return result


def _poly_multiply_schoolbook(poly1: Sequence[int], poly2: Sequence[int], prime: int) -> list[int]:
    """Multiply two small polynomials directly."""
    result = [0] * (len(poly1) + len(poly2) - 1)
    for i, val1 in enumerate(poly1):
        if val1 >= prime:
            val1 = val1 % prime

        if val1 == 0:
            continue

        for j, val2 in enumerate(poly2):
            if val2 >= prime:
                val2 = val2 % prime

            if val2 == 0:
                continue

            prod = (val1 * val2) % prime
            current = result[i + j] + prod
            if current >= prime:
                current -= prime
            result[i + j] = current
    return result


def poly_multiply(poly1: Sequence[int], poly2: Sequence[int], prime: int) -> list[int]:
    """Multiply two polynomials in a prime field."""
    if min(len(poly1), len(poly2)) <= 8:
        return _poly_multiply_schoolbook(poly1, poly2, prime)

    result_len = len(poly1) + len(poly2) - 1
    if result_len <= 64:
        return _poly_multiply_schoolbook(poly1, poly2, prime)

    domain_size = 1
    while domain_size < result_len:
        domain_size *= 2

    omega = get_root_of_unity(domain_size, prime)
    evals1 = evaluate_poly_fft(list(poly1), domain_size, omega, prime)
    evals2 = evaluate_poly_fft(list(poly2), domain_size, omega, prime)
    evals_prod = [(e1 * e2) % prime for e1, e2 in zip(evals1, evals2, strict=True)]
    return inverse_fft(evals_prod, omega, prime)[:result_len]


def poly_evaluate_single(poly: Sequence[int], x: int, prime: int) -> int:
    """Evaluate a polynomial at one point with Horner's method."""
    x %= prime
    result = 0
    for coef in reversed(poly):
        result = (result * x + coef) % prime
    return result


def lagrange_basis_polynomial(domain: Sequence[int], i: int, prime: int) -> list[int]:
    """Return the i-th Lagrange basis polynomial over the given domain."""
    omega = _root_of_unity_domain_omega(domain, prime)
    if omega is not None:
        n = len(domain)
        x_i = domain[i] % prime
        inv_n = pow(n, -1, prime)
        inv_xi = pow(x_i, -1, prime)

        coeffs = [0] * n
        current = inv_n
        for j in range(n):
            coeffs[j] = current
            current = (current * inv_xi) % prime
        return coeffs

    numerator = [1]
    denominator = 1
    x_i = domain[i] % prime
    for j, x_j in enumerate(domain):
        if j == i:
            continue
        numerator = poly_mul_linear(numerator, 1, (-x_j) % prime, prime)
        denominator = denominator * ((x_i - x_j) % prime) % prime

    return poly_scalar_mul(numerator, pow(denominator, -1, prime), prime)


def poly_divide_by_vanishing(poly: Sequence[int], domain_size: int) -> list[int]:
    """Return the quotient of poly divided by x^domain_size - 1."""
    if domain_size <= 0:
        raise ValueError("domain_size must be positive")

    if len(poly) < domain_size:
        return [0]

    quotient = list(poly[domain_size:])
    for i in range(1, len(poly) // domain_size):
        for j in range(len(quotient)):
            source_index = domain_size * (i + 1) + j
            if source_index < len(poly):
                quotient[j] += poly[source_index]

    while quotient and quotient[-1] == 0:
        quotient.pop()
    return quotient
