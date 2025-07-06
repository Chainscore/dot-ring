from __future__ import annotations

from typing import Sequence, Iterable, List
from dot_ring.ring_proof.constants import S_PRIME, D_512 as D

Prime = int
Vector = Sequence[int]
Poly = List[int]

def mod_inverse(val: int, prime: Prime) -> int:
    """Modular inverse via Fermat's theorem."""
    if pow(val, prime - 1, prime) != 1:
        raise ValueError("No inverse exists")
    return pow(val, prime - 2, prime)


def poly_add(poly1: Vector, poly2: Vector, prime: Prime) -> Poly:
    """Add two polynomials in GF(p)."""
    result_len = max(len(poly1), len(poly2))
    result: Poly = [0] * result_len

    for i in range(len(poly1)):
        result[i] = poly1[i]
    for i in range(len(poly2)):
        result[i] = (result[i] + poly2[i]) % prime
    return result


def poly_subtract(poly1: Vector, poly2: Vector, prime: Prime) -> Poly:
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
def poly_multiply(poly1: Vector, poly2: Vector, prime: Prime) -> Poly:
    """Multiply two polynomials in a prime field."""
    result_len = len(poly1) + len(poly2) - 1
    result = [0] * result_len
    for i in range(len(poly1)):
        for j in range(len(poly2)):
            result[i + j] = (result[i + j] + poly1[i] * poly2[j]) % prime
    return result


import time

def poly_division_general(c: Vector, d: Vector, p: Prime = S_PRIME):
    """
    c: list of coefficients for numerator (highest degree last)
    d: list of coefficients for denominator
    p: optional modulus (for finite field arithmetic)
    returns (quotient, remainder)
    """
    start=time.time()
    c = c[:]  # copy to avoid modifying input
    deg_c = len(c) - 1
    deg_d = len(d) - 1

    if deg_c < deg_d:
        return ([0], c)

    quotient = [0] * (deg_c - deg_d + 1)

    while len(c) >= len(d):
        coeff = c[-1]
        deg_diff = len(c) - len(d)

        if p:
            inv = mod_inverse(d[-1], p)
            coeff = (coeff * inv) % p
        else:
            coeff = coeff / d[-1]

        quotient[deg_diff] = coeff

        # Subtract (coeff * d * x^deg_diff) from c
        for i in range(len(d)):
            if p:
                c[deg_diff + i] = (c[deg_diff + i] - coeff * d[i]) % p
            else:
                c[deg_diff + i] -= coeff * d[i]

        # Remove trailing zeroes
        while c and c[-1] == 0:
            c.pop()
    return quotient#, c


def poly_scalar(poly: Vector, scalar: int, prime: Prime) -> Poly:
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

#30%
# import gmpy2
# def poly_evaluate(poly, x, prime):
#     x = gmpy2.mpz(x)
#     result = gmpy2.mpz(0)
#     for coef in reversed(poly):
#         result = (result * x + coef) % prime
#     return int(result)

#70%
from multiprocessing import Pool, cpu_count

def poly_evaluate_single(args: tuple[Vector, int, Prime]) -> int:
    poly, x, prime = args
    result=0
    for coef in reversed(poly):
        result = (result * x + coef) % prime
    return result  # Ensure plain Python int

def poly_evaluate(poly: Vector, xs: int | Iterable[int], prime: Prime) -> int | List[int]:
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
    inv_denominator = mod_inverse(denominator, prime)
    # Scale the numerator polynomial
    basis_poly = poly_scalar(numerator, inv_denominator, prime)

    return basis_poly


#vector subtraction
from typing import Union


def vect_sub(a: Union[int, Vector], b: Union[int, Vector], prime: Prime) -> Poly:
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
def vect_add(a: Union[int, Vector], b: Union[int, Vector], prime: Prime) -> Poly:
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
def vect_mul(a: Union[int, Vector], b: Union[int, Vector], prime: Prime) -> Poly:
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
