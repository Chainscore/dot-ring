# cython: language_level=3
# cython: boundscheck=False
# cython: wraparound=False
# cython: cdivision=True
# cython: initializedcheck=False

cimport cython

# Use gmpy2 for faster big integer operations
import gmpy2
from gmpy2 import mpz as __mpz

cdef _mpz(object x):
    return __mpz(x)

cdef _int(object x):
    return int(x)

_invert = gmpy2.invert

# Internal versions that work directly with mpz (no conversion overhead)
@cython.boundscheck(False)
@cython.wraparound(False)
cdef inline tuple _te_double_mpz(object x, object y, object z, object t, object a_coeff, object p):
    """Internal doubling with mpz inputs."""
    cdef object A, B, C, D, E, F, G, H
    cdef object x3, y3, z3, t3, z_sq, x_plus_y
    
    # A = X1^2
    A = (x * x) % p
    # B = Y1^2
    B = (y * y) % p
    # C = 2 * Z1^2
    z_sq = (z * z) % p
    C = (z_sq + z_sq) % p
    # D = a * A
    D = (a_coeff * A) % p
    # E = (X1 + Y1)^2 - A - B
    x_plus_y = (x + y) % p
    E = ((x_plus_y * x_plus_y) - A - B) % p
    # G = D + B
    G = (D + B) % p
    # F = G - C
    F = (G - C) % p
    # H = D - B
    H = (D - B) % p
    # X3 = E * F
    x3 = (E * F) % p
    # Y3 = G * H
    y3 = (G * H) % p
    # T3 = E * H
    t3 = (E * H) % p
    # Z3 = F * G
    z3 = (F * G) % p
    
    return (x3, y3, z3, t3)


@cython.boundscheck(False)
@cython.wraparound(False)
cdef inline tuple _te_add_mpz(
    object x1, object y1, object z1, object t1,
    object x2, object y2, object z2, object t2,
    object a_coeff, object d_coeff, object p
):
    """Internal addition with mpz inputs."""
    cdef object A, B, C, D, E, F, G, H
    cdef object x3, y3, z3, t3
    
    # A = X1*X2
    A = (x1 * x2) % p
    # B = Y1*Y2
    B = (y1 * y2) % p
    # C = d*T1*T2
    C = ((d_coeff * t1) % p * t2) % p
    # D = Z1*Z2
    D = (z1 * z2) % p
    # E = (X1+Y1)*(X2+Y2)-A-B
    E = (((x1 + y1) * (x2 + y2)) - A - B) % p
    # F = D-C
    F = (D - C) % p
    # G = D+C
    G = (D + C) % p
    # H = B-a*A
    H = (B - (a_coeff * A)) % p
    # X3 = E*F
    x3 = (E * F) % p
    # Y3 = G*H
    y3 = (G * H) % p
    # T3 = E*H
    t3 = (E * H) % p
    # Z3 = F*G
    z3 = (F * G) % p
    
    return (x3, y3, z3, t3)


# Public API - converts to mpz at entry, back to int at exit
cpdef tuple te_double_cy(
    object x, object y, object z, object t,
    object a_coeff, object p
):
    """
    Double a point in extended projective coordinates.
    
    Extended coordinates: (X:Y:Z:T) where x = X/Z, y = Y/Z, xy = T/Z
    
    Returns (X3, Y3, Z3, T3)
    """
    cdef object xm, ym, zm, tm, am, pm
    cdef tuple result
    
    # Convert to mpz once
    xm = _mpz(x)
    ym = _mpz(y)
    zm = _mpz(z)
    tm = _mpz(t)
    am = _mpz(a_coeff)
    pm = _mpz(p)
    
    result = _te_double_mpz(xm, ym, zm, tm, am, pm)
    
    # Convert back to int
    return (_int(result[0]), _int(result[1]), _int(result[2]), _int(result[3]))


cpdef tuple te_add_cy(
    object x1, object y1, object z1, object t1,
    object x2, object y2, object z2, object t2,
    object a_coeff, object d_coeff, object p
):
    """
    Add two points in extended projective coordinates.
    
    Returns (X3, Y3, Z3, T3)
    """
    cdef object x1m, y1m, z1m, t1m, x2m, y2m, z2m, t2m, am, dm, pm
    cdef tuple result
    
    # Convert to mpz once
    x1m = _mpz(x1)
    y1m = _mpz(y1)
    z1m = _mpz(z1)
    t1m = _mpz(t1)
    x2m = _mpz(x2)
    y2m = _mpz(y2)
    z2m = _mpz(z2)
    t2m = _mpz(t2)
    am = _mpz(a_coeff)
    dm = _mpz(d_coeff)
    pm = _mpz(p)
    
    result = _te_add_mpz(x1m, y1m, z1m, t1m, x2m, y2m, z2m, t2m, am, dm, pm)
    
    # Convert back to int
    return (_int(result[0]), _int(result[1]), _int(result[2]), _int(result[3]))


cpdef object mod_inverse_cy(object val, object p):
    """Compute modular inverse using gmpy2."""
    return _int(_invert(_mpz(val), _mpz(p)))


cpdef tuple projective_to_affine_cy(object x, object y, object z, object p):
    """Convert from projective to affine coordinates."""
    cdef object inv_z, pm, xm, ym, zm
    if z == 0:
        return (0, 1)
    pm = _mpz(p)
    xm = _mpz(x)
    ym = _mpz(y)
    zm = _mpz(z)
    inv_z = _invert(zm, pm)
    return (_int((xm * inv_z) % pm), _int((ym * inv_z) % pm))


cpdef tuple scalar_mult_windowed_cy(
    object k1, object k2,
    object p1_x, object p1_y, object p1_z, object p1_t,
    object p2_x, object p2_y, object p2_z, object p2_t,
    object a_coeff, object d_coeff, object p,
    int w = 2
):
    """
    Compute k1 * P1 + k2 * P2 using windowed simultaneous multi-scalar multiplication.
    All internal operations use gmpy2 mpz for ~3x speedup.
    """
    cdef int table_size = 1 << w
    cdef int i, j, num_windows, max_bits
    cdef object mask
    cdef object k1_win, k2_win
    cdef list p1_mults, p2_mults, table
    cdef tuple curr, pt, R, identity
    cdef list row
    cdef object am, dm, pm
    
    # Convert curve params to mpz once
    am = _mpz(a_coeff)
    dm = _mpz(d_coeff)
    pm = _mpz(p)
    
    # Identity in mpz
    identity = (_mpz(0), _mpz(1), _mpz(1), _mpz(0))
    
    # Convert input points to mpz
    curr = (_mpz(p1_x), _mpz(p1_y), _mpz(p1_z), _mpz(p1_t))
    p1_base = curr
    
    # Build P1 multiples (all in mpz)
    p1_mults = [identity]
    for i in range(1, table_size):
        p1_mults.append(curr)
        curr = _te_add_mpz(curr[0], curr[1], curr[2], curr[3],
                          p1_base[0], p1_base[1], p1_base[2], p1_base[3],
                          am, dm, pm)
    
    # Convert P2 to mpz
    curr = (_mpz(p2_x), _mpz(p2_y), _mpz(p2_z), _mpz(p2_t))
    p2_base = curr
    
    # Build P2 multiples
    p2_mults = [identity]
    for i in range(1, table_size):
        p2_mults.append(curr)
        curr = _te_add_mpz(curr[0], curr[1], curr[2], curr[3],
                          p2_base[0], p2_base[1], p2_base[2], p2_base[3],
                          am, dm, pm)
    
    # Build full table
    table = []
    for i in range(table_size):
        row = []
        for j in range(table_size):
            if i == 0:
                row.append(p2_mults[j])
            elif j == 0:
                row.append(p1_mults[i])
            else:
                pt = _te_add_mpz(
                    p1_mults[i][0], p1_mults[i][1], p1_mults[i][2], p1_mults[i][3],
                    p2_mults[j][0], p2_mults[j][1], p2_mults[j][2], p2_mults[j][3],
                    am, dm, pm
                )
                row.append(pt)
        table.append(row)
    
    # Calculate windows
    max_bits = max(k1.bit_length(), k2.bit_length())
    if max_bits == 0:
        max_bits = 1
    num_windows = (max_bits + w - 1) // w
    mask = (1 << w) - 1
    
    # Double-and-add (all in mpz)
    R = identity
    
    for i in range(num_windows - 1, -1, -1):
        # Double w times
        for j in range(w):
            R = _te_double_mpz(R[0], R[1], R[2], R[3], am, pm)
        
        # Extract windows
        k1_win = (k1 >> (i * w)) & mask
        k2_win = (k2 >> (i * w)) & mask
        
        # Add from table
        if k1_win != 0 or k2_win != 0:
            pt = table[k1_win][k2_win]
            R = _te_add_mpz(R[0], R[1], R[2], R[3],
                           pt[0], pt[1], pt[2], pt[3],
                           am, dm, pm)
    
    # Convert back to int only at the end
    return (_int(R[0]), _int(R[1]), _int(R[2]), _int(R[3]))


cpdef tuple scalar_mult_4_cy(
    object k1, object k2, object k3, object k4,
    object p1_x, object p1_y, object p1_z, object p1_t,
    object p2_x, object p2_y, object p2_z, object p2_t,
    object p3_x, object p3_y, object p3_z, object p3_t,
    object p4_x, object p4_y, object p4_z, object p4_t,
    object a_coeff, object d_coeff, object p,
    int w = 2
):
    """
    Compute k1*P1 + k2*P2 + k3*P3 + k4*P4 using 2x2 windowed MSM.
    All internal operations use gmpy2 mpz for ~3x speedup.
    """
    cdef int table_size = 1 << w
    cdef int i, j, num_windows, max_bits
    cdef object mask
    cdef object k1_win, k2_win, k3_win, k4_win
    cdef list p1_mults, p2_mults, p3_mults, p4_mults
    cdef list table12, table34, row, row34
    cdef tuple curr, pt, R, identity
    cdef object am, dm, pm
    
    # Convert curve params to mpz once
    am = _mpz(a_coeff)
    dm = _mpz(d_coeff)
    pm = _mpz(p)
    
    # Identity in mpz
    identity = (_mpz(0), _mpz(1), _mpz(1), _mpz(0))
    
    # Build P1 multiples
    curr = (_mpz(p1_x), _mpz(p1_y), _mpz(p1_z), _mpz(p1_t))
    p1_base = curr
    p1_mults = [identity]
    for i in range(1, table_size):
        p1_mults.append(curr)
        curr = _te_add_mpz(curr[0], curr[1], curr[2], curr[3],
                          p1_base[0], p1_base[1], p1_base[2], p1_base[3],
                          am, dm, pm)
    
    # Build P2 multiples
    curr = (_mpz(p2_x), _mpz(p2_y), _mpz(p2_z), _mpz(p2_t))
    p2_base = curr
    p2_mults = [identity]
    for i in range(1, table_size):
        p2_mults.append(curr)
        curr = _te_add_mpz(curr[0], curr[1], curr[2], curr[3],
                          p2_base[0], p2_base[1], p2_base[2], p2_base[3],
                          am, dm, pm)
    
    # Build table12
    table12 = []
    for i in range(table_size):
        row = []
        for j in range(table_size):
            if i == 0:
                row.append(p2_mults[j])
            elif j == 0:
                row.append(p1_mults[i])
            else:
                pt = _te_add_mpz(
                    p1_mults[i][0], p1_mults[i][1], p1_mults[i][2], p1_mults[i][3],
                    p2_mults[j][0], p2_mults[j][1], p2_mults[j][2], p2_mults[j][3],
                    am, dm, pm
                )
                row.append(pt)
        table12.append(row)
    
    # Build P3 multiples
    curr = (_mpz(p3_x), _mpz(p3_y), _mpz(p3_z), _mpz(p3_t))
    p3_base = curr
    p3_mults = [identity]
    for i in range(1, table_size):
        p3_mults.append(curr)
        curr = _te_add_mpz(curr[0], curr[1], curr[2], curr[3],
                          p3_base[0], p3_base[1], p3_base[2], p3_base[3],
                          am, dm, pm)
    
    # Build P4 multiples
    curr = (_mpz(p4_x), _mpz(p4_y), _mpz(p4_z), _mpz(p4_t))
    p4_base = curr
    p4_mults = [identity]
    for i in range(1, table_size):
        p4_mults.append(curr)
        curr = _te_add_mpz(curr[0], curr[1], curr[2], curr[3],
                          p4_base[0], p4_base[1], p4_base[2], p4_base[3],
                          am, dm, pm)
    
    # Build table34
    table34 = []
    for i in range(table_size):
        row34 = []
        for j in range(table_size):
            if i == 0:
                row34.append(p4_mults[j])
            elif j == 0:
                row34.append(p3_mults[i])
            else:
                pt = _te_add_mpz(
                    p3_mults[i][0], p3_mults[i][1], p3_mults[i][2], p3_mults[i][3],
                    p4_mults[j][0], p4_mults[j][1], p4_mults[j][2], p4_mults[j][3],
                    am, dm, pm
                )
                row34.append(pt)
        table34.append(row34)
    
    # Calculate windows
    max_bits = max(k1.bit_length(), k2.bit_length(), k3.bit_length(), k4.bit_length())
    if max_bits == 0:
        max_bits = 1
    num_windows = (max_bits + w - 1) // w
    mask = (1 << w) - 1
    
    # Double-and-add (all in mpz)
    R = identity
    
    for i in range(num_windows - 1, -1, -1):
        for j in range(w):
            R = _te_double_mpz(R[0], R[1], R[2], R[3], am, pm)
        
        k1_win = (k1 >> (i * w)) & mask
        k2_win = (k2 >> (i * w)) & mask
        k3_win = (k3 >> (i * w)) & mask
        k4_win = (k4 >> (i * w)) & mask
        
        if k1_win != 0 or k2_win != 0:
            pt = table12[k1_win][k2_win]
            R = _te_add_mpz(R[0], R[1], R[2], R[3],
                           pt[0], pt[1], pt[2], pt[3],
                           am, dm, pm)
        if k3_win != 0 or k4_win != 0:
            pt = table34[k3_win][k4_win]
            R = _te_add_mpz(R[0], R[1], R[2], R[3],
                           pt[0], pt[1], pt[2], pt[3],
                           am, dm, pm)
    
    # Convert back to int only at the end
    return (_int(R[0]), _int(R[1]), _int(R[2]), _int(R[3]))
