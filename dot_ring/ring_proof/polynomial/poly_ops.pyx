# cython: language_level=3
# cython: boundscheck=False
# cython: wraparound=False
# cython: cdivision=True
# cython: initializedcheck=False

def poly_add(list poly1, list poly2, object prime):
    """Add two polynomials in a prime field (optimized Cython version)."""
    cdef int len1 = len(poly1)
    cdef int len2 = len(poly2)
    cdef int result_len = max(len1, len2)
    cdef int i
    cdef object val
    cdef list result = [0] * result_len

    # Add poly1 coefficients
    for i in range(len1):
        result[i] = poly1[i]

    # Add poly2 coefficients
    for i in range(len2):
        val = result[i] + poly2[i]
        if val >= prime:
            val -= prime
        result[i] = val

    return result


def poly_subtract(list poly1, list poly2, object prime):
    """Subtract poly2 from poly1 in a prime field (optimized Cython version)."""
    cdef int len1 = len(poly1)
    cdef int len2 = len(poly2)
    cdef int result_len = max(len1, len2)
    cdef int i
    cdef object val, val1, val2
    cdef list result = [0] * result_len

    # Add poly1 coefficients
    for i in range(len1):
        result[i] = poly1[i]

    # Subtract poly2 coefficients
    for i in range(len2):
        val1 = result[i]
        val2 = poly2[i]
        if val1 >= val2:
            result[i] = val1 - val2
        else:
            result[i] = prime - (val2 - val1)

    return result


def poly_scalar_mul(list poly, object scalar, object prime):
    """Multiply a polynomial by a scalar in a prime field (optimized Cython version)."""
    cdef int n = len(poly)
    cdef int i
    cdef object coef
    cdef list result = [None] * n

    # Normalize scalar
    if scalar >= prime:
        scalar = scalar % prime

    # Special case: scalar is 0 or 1
    if scalar == 0:
        return [0] * n
    elif scalar == 1:
        return [poly[i] % prime if poly[i] >= prime else poly[i] for i in range(n)]

    # General case
    for i in range(n):
        coef = poly[i]
        if coef >= prime:
            coef = coef % prime
        result[i] = (coef * scalar) % prime

    return result


def poly_evaluate_single(list poly, object x, object prime):
    """Evaluate polynomial at point x using Horner's method (optimized Cython version)."""
    cdef int n = len(poly)
    cdef int i
    cdef object result = 0
    cdef object coef

    # Normalize x
    if x >= prime:
        x = x % prime

    # Horner's method: evaluate from highest degree to lowest
    for i in range(n - 1, -1, -1):
        coef = poly[i]
        if coef >= prime:
            coef = coef % prime
        result = (result * x + coef) % prime

    return result


def poly_multiply_naive(list poly1, list poly2, object prime):
    """Multiply two polynomials using naive O(n²) algorithm (optimized for small polynomials)."""
    cdef int len1 = len(poly1)
    cdef int len2 = len(poly2)
    cdef int result_len = len1 + len2 - 1
    cdef int i, j
    cdef object val1, val2, prod, current
    cdef list result = [0] * result_len

    for i in range(len1):
        val1 = poly1[i]
        if val1 >= prime:
            val1 = val1 % prime

        if val1 == 0:
            continue

        for j in range(len2):
            val2 = poly2[j]
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


def poly_eval_domain(list poly, list domain, object prime):
    """Evaluate polynomial at multiple points (for non-FFT domains)."""
    cdef int n_points = len(domain)
    cdef int i
    cdef object x
    cdef list result = [None] * n_points

    for i in range(n_points):
        x = domain[i]
        if x >= prime:
            x = x % prime
        result[i] = poly_evaluate_single(poly, x, prime)

    return result


def vect_scalar_mul_inplace(list vec, object scalar, object prime):
    """Multiply each element by scalar modulo prime (in-place version for reduced allocations)."""
    cdef int n = len(vec)
    cdef int i
    cdef object val

    if scalar >= prime:
        scalar = scalar % prime

    if scalar == 0:
        for i in range(n):
            vec[i] = 0
    elif scalar != 1:
        for i in range(n):
            val = vec[i]
            if val >= prime:
                val = val % prime
            vec[i] = (val * scalar) % prime
    else:
        # scalar == 1, just normalize
        for i in range(n):
            if vec[i] >= prime:
                vec[i] = vec[i] % prime

    return vec


def vect_add_inplace(list a, list b, object prime):
    """Add vector b to vector a in-place (modifies a)."""
    cdef int n = len(a)
    cdef int m = len(b)
    cdef int i
    cdef object val_a, val_b, result

    if m != n:
        raise ValueError("Vector lengths must match")

    for i in range(n):
        val_a = a[i]
        val_b = b[i]
        if val_a >= prime:
            val_a = val_a % prime
        if val_b >= prime:
            val_b = val_b % prime
        result = val_a + val_b
        if result >= prime:
            result -= prime
        a[i] = result

    return a


def poly_mul_linear(list poly, object a, object b, object prime):
    """Multiply poly by (ax + b) in O(n) time (optimized version)."""
    cdef int n = len(poly)
    cdef int i
    cdef object coef, term1, term2, prev_coef
    cdef list result = [None] * (n + 1)

    # Normalize a and b
    if a >= prime:
        a = a % prime
    if b >= prime:
        b = b % prime

    # Handle first element: result[0] = b * poly[0]
    coef = poly[0]
    if coef >= prime:
        coef = coef % prime
    result[0] = (b * coef) % prime

    # Handle middle elements: result[i] = a * poly[i-1] + b * poly[i]
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

    # Handle last element: result[n] = a * poly[n-1]
    coef = poly[n - 1]
    if coef >= prime:
        coef = coef % prime
    result[n] = (a * coef) % prime

    return result
