from dot_ring.ring_proof.constants import S_PRIME, D_512, D_2048, OMEGA, OMEGA_2048
from dot_ring.ring_proof.polynomial.fft import evaluate_poly_fft, inverse_fft


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


GENERATOR = 5

_root_of_unity_cache = {}

def get_root_of_unity(n, prime):
    """Get n-th primitive root of unity."""
    key = (n, prime)
    if key in _root_of_unity_cache:
        return _root_of_unity_cache[key]

    # We need n to be a power of 2 and divide prime-1
    # prime-1 is divisible by 2^32, so any power of 2 <= 2^32 works
    exponent = (prime - 1) // n
    root = pow(GENERATOR, exponent, prime)
    _root_of_unity_cache[key] = root
    return root


#(On^2)
def poly_multiply(poly1, poly2, prime):
    """Multiply two polynomials in a prime field."""
    result_len = len(poly1) + len(poly2) - 1
    
    # Use FFT if polynomials are large enough
    # Threshold chosen empirically - FFT overhead is not worth it for very small polys
    if result_len > 64:
        # Find next power of 2
        domain_size = 1
        while domain_size < result_len:
            domain_size *= 2
            
        # We can support up to 2^32
        omega = get_root_of_unity(domain_size, prime)
        
        evals1 = evaluate_poly_fft(poly1, domain_size, omega, prime)
        evals2 = evaluate_poly_fft(poly2, domain_size, omega, prime)
        
        evals_prod = [(e1 * e2) % prime for e1, e2 in zip(evals1, evals2)]
        
        coeffs = inverse_fft(evals_prod, omega, prime)
        
        # Truncate to expected length (higher terms should be 0)
        return coeffs[:result_len]

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


def poly_evaluate_single(poly: list, x: int, prime: int):
    result=0
    for coef in reversed(poly):
        result = (result * x + coef) % prime
    return result


def poly_evaluate(poly: list, xs: list | int, prime: int):
    """Evaluate polynomial at points xs.
    
    Uses FFT when xs is one of the predefined evaluation domains (D_512, D_2048).
    Falls back to Horner evaluation for arbitrary points.
    
    Args:
        poly: Polynomial coefficients (lowest degree first)
        xs: Either a list of evaluation points or a single point
        prime: Field modulus
        
    Returns:
        List of evaluations (or single value if xs is a single point)
    """
    # Handle single point evaluation
    if isinstance(xs, int):
        return poly_evaluate_single(poly, xs, prime)
    
    # Check if xs is one of the FFT-friendly domains
    # Compare by identity first (fast path), then by equality
    if xs is D_2048 or (len(xs) == 2048 and xs == D_2048):
        # Use FFT for D_2048
        return evaluate_poly_fft(poly, 2048, OMEGA_2048, prime, coset_offset=1)
    elif xs is D_512 or (len(xs) == 512 and xs == D_512):
        # Use FFT for D_512
        return evaluate_poly_fft(poly, 512, OMEGA, prime, coset_offset=1)
    else:
        # Fall back to Horner evaluation for arbitrary points
        results = [poly_evaluate_single(poly, x, prime) for x in xs]
        return results


def poly_mul_linear(poly, a, b, prime):
    """Multiply poly by (ax + b) in O(n) time."""
    # result = poly * (ax + b) = a * (poly * x) + b * poly
    # poly * x is [0] + poly
    # result[i] = a * poly[i-1] + b * poly[i]
    
    n = len(poly)
    result = [0] * (n + 1)
    
    # Handle first element (i=0): result[0] = b * poly[0]
    result[0] = (b * poly[0]) % prime
    
    for i in range(1, n):
        result[i] = (a * poly[i-1] + b * poly[i]) % prime
        
    # Handle last element (i=n): result[n] = a * poly[n-1]
    result[n] = (a * poly[n-1]) % prime
    
    return result


def lagrange_basis_polynomial(x_coords, i, prime: int):
    """
    Compute the i-th Lagrange basis polynomial.

    L_i(x) = (x - x_j) / (x_i - x_j)
    """
    # Optimization for roots of unity domains
    if x_coords is D_512 or (len(x_coords) == 512 and x_coords == D_512) or \
       x_coords is D_2048 or (len(x_coords) == 2048 and x_coords == D_2048):
        n = len(x_coords)
        x_i = x_coords[i]
        
        # L_i(x) = 1/n * sum_{j=0}^{n-1} (x_i^{-j}) x^j
        # coeff[j] = 1/n * (x_i^{-1})^j
        
        inv_n = pow(n, -1, prime)
        inv_xi = pow(x_i, -1, prime)
        
        coeffs = [0] * n
        current = inv_n
        for j in range(n):
            coeffs[j] = current
            current = (current * inv_xi) % prime
            
        return coeffs

    n = len(x_coords)
    numerator = [1]  # Start with polynomial 1
    denominator = 1

    for j in range(n):
        if j != i:
            # Multiply numerator by (x - x_j)
            # term = [(-x_coords[j]) % prime, 1]
            # numerator = poly_multiply(numerator, term, prime)
            
            # Use optimized linear multiplication: multiply by (1*x - x_j)
            numerator = poly_mul_linear(numerator, 1, (-x_coords[j]) % prime, prime)

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
