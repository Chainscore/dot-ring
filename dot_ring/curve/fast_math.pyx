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


cpdef object map_to_curve_ell2_fast(object u, object J, object K, object Z, object p):
    """
    Fast Elligator 2 map to curve implementation.
    """
    cdef object pm = _get_mpz_prime(p)
    cdef object um = _mpz(u)
    cdef object Jm = _mpz(J)
    cdef object Km = _mpz(K)
    cdef object Zm = _mpz(Z)
    
    # Compute constants
    # c1 = (J * K^-1) % p
    cdef object c1 = (Jm * _invert(Km, pm)) % pm
    # c2 = (K^2)^-1 % p
    cdef object c2 = _invert((Km * Km) % pm, pm)

    # Main mapping computation
    # tv1 = (Z * u^2) % p
    cdef object tv1 = (Zm * um * um) % pm
    
    cdef bint e1 = (tv1 == -1) or (tv1 == pm - 1)
    if e1:
        tv1 = _mpz(0)
        
    # x1 = (-c1 * (tv1 + 1)^-1) % p
    cdef object x1 = (-c1 * _invert(tv1 + 1, pm)) % pm
    
    # gx1 = (((x1 + c1) * x1 + c2) * x1) % p
    cdef object gx1 = (((x1 + c1) * x1 + c2) * x1) % pm
    
    # x2 = (-x1 - c1) % p
    cdef object x2 = (-x1 - c1) % pm
    
    # gx2 = (tv1 * gx1) % p
    cdef object gx2 = (tv1 * gx1) % pm
    
    # Choose correct values
    # e2 = is_square(gx1)
    cdef bint e2 = is_square(gx1, p)
    
    cdef object x, y2
    if e2:
        x = x1
        y2 = gx1
    else:
        x = x2
        y2 = gx2
        
    # Compute square root
    cdef object y = sqrt_mod(y2, p)
    if y is None:
        # This should not happen if map is correct
        raise ValueError("Failed to compute sqrt in map_to_curve")
        
    cdef object ym = _mpz(y)
    
    # Adjust sign
    # e3 = (y & 1) == 1
    cdef bint e3 = (ym % 2) == 1
    
    if e2 ^ e3:
        ym = -ym % pm
        
    # Scale coordinates
    # s = (x * K) % p
    cdef object s = (x * Km) % pm
    # t = (y * K) % p
    cdef object t = (ym * Km) % pm
    
    return (int(s), int(t))
