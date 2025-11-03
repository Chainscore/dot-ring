
from dot_ring.ring_proof.constants import S_PRIME
def mod_inverse(val, prime):
    """Find the modular multiplicative inverse of a under modulo m."""
    if pow(val, prime - 1, prime) != 1:
        raise ValueError("No inverse exists")
    return pow(val, prime - 2, prime)


def poly_add(poly1, poly2, prime):
    """Add two polynomials in a prime field."""
    # Make them the same length
    result_len = max(len(poly1), len(poly2))
    result = [0] * result_len

    for i in range(len(poly1)):
        result[i] = poly1[i]
    for i in range(len(poly2)):
        result[i] = (result[i] + poly2[i]) % prime
    return result


def poly_subtract(poly1, poly2, prime):
    """Subtract poly2 from poly1 in a prime field."""
    # Make them the same length
    result_len = max(len(poly1), len(poly2))
    result = [0] * result_len

    for i in range(len(poly1)):
        result[i] = poly1[i]

    for i in range(len(poly2)):
        result[i] = (result[i] - poly2[i]) % prime
    return result


#(On^2)
def poly_multiply(poly1, poly2, prime):
    """Multiply two polynomials in a prime field."""
    result_len = len(poly1) + len(poly2) - 1
    result = [0] * result_len
    for i in range(len(poly1)):
        for j in range(len(poly2)):
            result[i + j] = (result[i + j] + poly1[i] * poly2[j]) % prime
    return result

def poly_division_general(coeffs, domain_size):
    """
    Divide polynomial f(x) by vanishing polynomial Z_H(x) = x^domain_size - 1

    Args:
        coeffs: list[int or Fp] - coefficients of f(x), lowest degree first
        domain_size: int - size of the evaluation domain (n)

    Returns:
        (quotient) a lists of coefficients
    """

    n = domain_size
    deg_f = len(coeffs)

    # Case 1: degree(f) < domain_size -> quotient = 0, remainder = f
    if deg_f < n:
        return [0], coeffs[:]

    # Step 1️: initial quotient is the higher-degree coefficients
    quotient = coeffs[n:].copy()

    # Step 2️: accumulate wrapped parts if polynomial is longer than 2n
    # Equivalent to folding coefficients every n steps
    for i in range(1, deg_f // n):
        for j in range(len(quotient)):
            src_index = n * (i + 1) + j
            if src_index < deg_f:
                quotient[j] += coeffs[src_index]

    #trim trailing zeros for cleaner output
    while quotient and quotient[-1] == 0:
        quotient.pop()
    return quotient


def poly_scalar(poly, scalar, prime):
    """Multiply a polynomial by a scalar in a prime field."""
    result = [(coef * scalar) % prime for coef in poly]
    return result

#initial
# def poly_evaluate(poly, x, prime):
#     """Evaluate a polynomial at point x using Horner's method."""
#     result = 0
#     for coef in  reversed(poly):
#         result = (result * x + coef) % prime
#     return result

#
# import gmpy2
# def poly_evaluate(poly, x, prime):
#     x = gmpy2.mpz(x)
#     result = gmpy2.mpz(0)
#     for coef in reversed(poly):
#         result = (result * x + coef) % prime
#     return int(result)


from multiprocessing import Pool, cpu_count
def poly_evaluate_single(args):
    poly, x, prime = args
    result=0
    for coef in reversed(poly):
        result = (result * x + coef) % prime
    return result  # Ensure plain Python int
#
def poly_evaluate(poly, xs, prime):
    prime = int(prime)
    # Single-point evaluation
    if isinstance(xs, int):
        return poly_evaluate_single((poly, xs, prime))

    # Multi-point evaluation
    with Pool(processes=cpu_count()) as pool:
        args = [(poly, x, prime) for x in xs]
        results = pool.map(poly_evaluate_single, args)
        return results

def lagrange_basis_polynomial(x_coords, i, prime=S_PRIME):
    """
    Compute the i-th Lagrange basis polynomial.

    L_i(x) = (x - x_j) / (x_i - x_j)
    """
    n = len(x_coords)
    numerator = [1]  # Start with polynomial 1
    denominator = 1

    for j in range(n):
        if j != i:
            # Multiply numerator by (x - x_j)
            term = [(-x_coords[j]) % prime, 1]
            numerator = poly_multiply(numerator, term, prime)

            # Multiply denominator by (x_i - x_j)
            diff = (x_coords[i] - x_coords[j]) % prime
            denominator = (denominator * diff) % prime

    # Calculate modular inverse of denominator
    # inv_denominator = mod_inverse(denominator, prime)
    inv_denominator = pow(denominator, -1, prime)
    # Scale the numerator polynomial
    basis_poly = poly_scalar(numerator, inv_denominator, prime)

    return basis_poly


#vector subtraction
def vect_sub(a,b, prime):
    if isinstance(a, int) and isinstance(b, list):
        n=len(b)
        a=[a]*n
        result=[(i-j)%prime for i,j in zip(a,b)]
        return result
    elif isinstance(a,list) and isinstance(b, int):
        n=len(a)
        b=[b]*n
        result= [(i-j)% prime for i, j in zip(a,b)]
        return result
    else:
        result=[(i-j)%prime for i, j in zip(a,b)]
        return result

#vector addition
def vect_add(a, b, prime):
    if isinstance(a, int) and isinstance(b, list):
        n=len(b)
        a=[a]*n
        result=[(i+j)%prime for i,j in zip(a,b)]
        return result
    elif isinstance(a,list) and isinstance(b, int):
        n=len(a)
        b=[b]*n
        result= [(i+j)% prime for i, j in zip(a,b)]
        return result
    else:
        result=[(i+j)%prime for i, j in zip(a,b)]
        return result

#vector multiplication
def vect_mul(a, b, prime):
    if isinstance(a, int) and isinstance(b, list):
        n=len(b)
        a=[a]*n
        result=[(i*j)%prime for i,j in zip(a,b)]
        return result
    elif isinstance(a,list) and isinstance(b, int):
        n=len(a)
        b=[b]*n
        result= [(i*j)% prime for i, j in zip(a,b)]
        return result
    else:
        result=[(i*j)%prime for i, j in zip(a,b)]
        return result

def vect_scalar_mul(vec, scalar, mod=None):
    """Multiply each element in the vector by the scalar"""
    return [(x * scalar) % mod if mod else x * scalar for x in vec]
