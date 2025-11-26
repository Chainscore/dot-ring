# cython: language_level=3
# cython: boundscheck=False
# cython: wraparound=False
# cython: cdivision=True
# cython: initializedcheck=False

from gmpy2 import mpz as _mpz, powmod as _powmod, invert as _invert

_prime_cache = {}

cdef object _get_mpz_prime(object p):
    """Get cached mpz version of prime."""
    if p not in _prime_cache:
        _prime_cache[p] = _mpz(p)
    return _prime_cache[p]


# -----------------------------------------------------------------------------
# Core modular arithmetic
# -----------------------------------------------------------------------------

cpdef object powmod(object base, object exp, object mod):
    """Fast modular exponentiation using gmpy2."""
    return int(_powmod(_mpz(base), _mpz(exp), _mpz(mod)))


cpdef object invert(object x, object mod):
    """Fast modular inverse using gmpy2."""
    return int(_invert(_mpz(x), _mpz(mod)))


cpdef bint is_square(object x, object p):
    """Check if x is a quadratic residue mod p using Euler's criterion."""
    if x == 0:
        return True
    cdef object pm = _get_mpz_prime(p)
    cdef object exp = _mpz((p - 1) // 2)
    return int(_powmod(_mpz(x), exp, pm)) == 1


cpdef object sqrt_mod(object x, object p):
    """
    Compute modular square root using Tonelli-Shanks algorithm.
    Returns None if x is not a quadratic residue.
    """
    cdef object pm, xm, Q, z, M, c, t, R, b, temp
    cdef int S, i
    
    if x == 0:
        return 0
    
    pm = _get_mpz_prime(p)
    xm = _mpz(x)
    
    # Check if x is a quadratic residue
    if int(_powmod(xm, _mpz((p - 1) // 2), pm)) != 1:
        return None
    
    # Simple case: p ≡ 3 (mod 4)
    if p % 4 == 3:
        return int(_powmod(xm, _mpz((p + 1) // 4), pm))
    
    # Tonelli-Shanks algorithm for general case
    Q = p - 1
    S = 0
    while Q % 2 == 0:
        Q //= 2
        S += 1
    
    # Find a non-residue z
    z = 2
    while is_square(z, p):
        z += 1
    
    M = S
    c = int(_powmod(_mpz(z), _mpz(Q), pm))
    t = int(_powmod(xm, _mpz(Q), pm))
    R = int(_powmod(xm, _mpz((Q + 1) // 2), pm))
    
    while True:
        if t == 0:
            return 0
        if t == 1:
            return R
        
        # Find least i such that t^(2^i) = 1
        i = 1
        temp = (t * t) % p
        while temp != 1:
            temp = (temp * temp) % p
            i += 1
        
        # Update values
        b = c
        for _ in range(M - i - 1):
            b = (b * b) % p
        M = i
        c = (b * b) % p
        t = (t * c) % p
        R = (R * b) % p
