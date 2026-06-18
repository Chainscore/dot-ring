# cython: language_level=3
# cython: boundscheck=False
# cython: wraparound=False
# cython: cdivision=True
# cython: initializedcheck=False

from libc.stdint cimport int16_t, uint64_t, uint8_t
from libc.stdlib cimport free, malloc

from dot_ring.curve.native_field.scalar cimport (
    bls_scalar_t,
    bls_scalar_add,
    bls_scalar_exp,
    bls_scalar_from_bytes,
    bls_scalar_from_mont,
    bls_scalar_from_uint64,
    bls_scalar_inv,
    bls_scalar_mul_mont,
    bls_scalar_sub,
    bls_scalar_to_bytes,
    bls_scalar_to_mont,
)

# Use gmpy2 for faster big integer operations
import gmpy2
from gmpy2 import mpz as _mpz

_invert = gmpy2.invert

_BLS_SCALAR_MODULUS_INT = 0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001


cdef struct TEProjNative:
    bls_scalar_t x
    bls_scalar_t y
    bls_scalar_t z
    bls_scalar_t t


cdef inline void _scalar_zero(bls_scalar_t *out):
    bls_scalar_from_uint64(out, 0)


cdef inline void _scalar_one_mont(bls_scalar_t *out):
    bls_scalar_from_uint64(out, 1)
    bls_scalar_to_mont(out, out)


cdef inline void _scalar_from_py_mont(bls_scalar_t *out, object value):
    cdef bytes b
    value = int(value) % _BLS_SCALAR_MODULUS_INT
    b = value.to_bytes(32, "little")
    bls_scalar_from_bytes(out, <const uint8_t *>b)
    bls_scalar_to_mont(out, out)


cdef inline void _scalar_from_py_raw(bls_scalar_t *out, object value):
    cdef bytes b
    value = int(value) % _BLS_SCALAR_MODULUS_INT
    b = value.to_bytes(32, "little")
    bls_scalar_from_bytes(out, <const uint8_t *>b)


cdef inline object _scalar_to_py_int(const bls_scalar_t *value):
    cdef bls_scalar_t raw
    cdef uint8_t b[32]
    bls_scalar_from_mont(&raw, value)
    bls_scalar_to_bytes(b, &raw)
    return int.from_bytes((<char *>b)[:32], "little")


cdef inline bint _scalar_eq(const bls_scalar_t *a, const bls_scalar_t *b):
    return (
        a.val[0] == b.val[0]
        and a.val[1] == b.val[1]
        and a.val[2] == b.val[2]
        and a.val[3] == b.val[3]
    )


cdef inline bint _scalar_is_zero(const bls_scalar_t *value):
    return (
        value.val[0] == 0
        and value.val[1] == 0
        and value.val[2] == 0
        and value.val[3] == 0
    )


cdef inline tuple _projective_native_to_affine_tuple(const TEProjNative *point):
    cdef bls_scalar_t zero
    cdef bls_scalar_t z_inv
    cdef bls_scalar_t x_affine
    cdef bls_scalar_t y_affine
    _scalar_zero(&zero)
    if _scalar_eq(&point.z, &zero):
        return (0, 1)
    bls_scalar_inv(&z_inv, &point.z)
    bls_scalar_mul_mont(&x_affine, &point.x, &z_inv)
    bls_scalar_mul_mont(&y_affine, &point.y, &z_inv)
    return (_scalar_to_py_int(&x_affine), _scalar_to_py_int(&y_affine))


cdef inline void _point_identity(TEProjNative *out):
    _scalar_zero(&out.x)
    _scalar_one_mont(&out.y)
    _scalar_one_mont(&out.z)
    _scalar_zero(&out.t)


cdef inline void _point_copy(TEProjNative *out, const TEProjNative *value):
    out.x = value.x
    out.y = value.y
    out.z = value.z
    out.t = value.t


cdef inline void _point_neg_native(TEProjNative *out, const TEProjNative *value):
    cdef bls_scalar_t zero
    _scalar_zero(&zero)
    bls_scalar_sub(&out.x, &zero, &value.x)
    out.y = value.y
    out.z = value.z
    bls_scalar_sub(&out.t, &zero, &value.t)


cdef inline void _te_double_native(TEProjNative *out, const TEProjNative *point, const bls_scalar_t *a_coeff):
    cdef bls_scalar_t A, B, C, D, E, F, G, H, z_sq, x_plus_y

    bls_scalar_mul_mont(&A, &point.x, &point.x)
    bls_scalar_mul_mont(&B, &point.y, &point.y)
    bls_scalar_mul_mont(&z_sq, &point.z, &point.z)
    bls_scalar_add(&C, &z_sq, &z_sq)
    bls_scalar_mul_mont(&D, a_coeff, &A)
    bls_scalar_add(&x_plus_y, &point.x, &point.y)
    bls_scalar_mul_mont(&E, &x_plus_y, &x_plus_y)
    bls_scalar_sub(&E, &E, &A)
    bls_scalar_sub(&E, &E, &B)
    bls_scalar_add(&G, &D, &B)
    bls_scalar_sub(&F, &G, &C)
    bls_scalar_sub(&H, &D, &B)
    bls_scalar_mul_mont(&out.x, &E, &F)
    bls_scalar_mul_mont(&out.y, &G, &H)
    bls_scalar_mul_mont(&out.t, &E, &H)
    bls_scalar_mul_mont(&out.z, &F, &G)


cdef inline void _te_add_native(
    TEProjNative *out,
    const TEProjNative *left,
    const TEProjNative *right,
    const bls_scalar_t *a_coeff,
    const bls_scalar_t *d_coeff,
):
    cdef bls_scalar_t A, B, C, D, E, F, G, H, tmp1, tmp2

    bls_scalar_mul_mont(&A, &left.x, &right.x)
    bls_scalar_mul_mont(&B, &left.y, &right.y)
    bls_scalar_mul_mont(&tmp1, d_coeff, &left.t)
    bls_scalar_mul_mont(&C, &tmp1, &right.t)
    bls_scalar_mul_mont(&D, &left.z, &right.z)
    bls_scalar_add(&tmp1, &left.x, &left.y)
    bls_scalar_add(&tmp2, &right.x, &right.y)
    bls_scalar_mul_mont(&E, &tmp1, &tmp2)
    bls_scalar_sub(&E, &E, &A)
    bls_scalar_sub(&E, &E, &B)
    bls_scalar_sub(&F, &D, &C)
    bls_scalar_add(&G, &D, &C)
    bls_scalar_mul_mont(&tmp1, a_coeff, &A)
    bls_scalar_sub(&H, &B, &tmp1)
    bls_scalar_mul_mont(&out.x, &E, &F)
    bls_scalar_mul_mont(&out.y, &G, &H)
    bls_scalar_mul_mont(&out.t, &E, &H)
    bls_scalar_mul_mont(&out.z, &F, &G)


cdef inline void _point_from_py(
    TEProjNative *out,
    object x,
    object y,
    object z,
    object t,
):
    _scalar_from_py_mont(&out.x, x)
    _scalar_from_py_mont(&out.y, y)
    _scalar_from_py_mont(&out.z, z)
    _scalar_from_py_mont(&out.t, t)


cdef inline void _scalar_limbs_from_py(uint64_t limbs[4], object value):
    cdef bytes b
    cdef const uint8_t *p
    cdef int i, j

    value = int(value)
    if value < 0:
        raise ValueError("native scalar windowing expects non-negative scalars")
    b = value.to_bytes(32, "little")
    p = <const uint8_t *>b
    for i in range(4):
        limbs[i] = 0
        for j in range(8):
            limbs[i] |= (<uint64_t>p[i * 8 + j]) << (j * 8)


cdef inline int _scalar_limbs_bit_length(const uint64_t limbs[4]):
    cdef int i, bits
    cdef uint64_t word
    for i in range(3, -1, -1):
        word = limbs[i]
        if word != 0:
            bits = i * 64
            while word != 0:
                bits += 1
                word >>= 1
            return bits
    return 0


cdef inline unsigned int _scalar_window2(const uint64_t limbs[4], int bit_pos):
    cdef int limb_idx = bit_pos >> 6
    cdef int shift = bit_pos & 63
    cdef uint64_t value
    if limb_idx >= 4:
        return 0
    value = limbs[limb_idx] >> shift
    if shift > 62 and limb_idx + 1 < 4:
        value |= limbs[limb_idx + 1] << (64 - shift)
    return <unsigned int>(value & 3)


cdef inline unsigned int _scalar_window_bits(const uint64_t *limbs, int bit_pos, int window_bits):
    cdef int limb_idx = bit_pos >> 6
    cdef int shift = bit_pos & 63
    cdef uint64_t value = 0
    cdef uint64_t mask = (<uint64_t>1 << window_bits) - 1
    if limb_idx >= 4:
        return 0
    value = limbs[limb_idx] >> shift
    if shift + window_bits > 64 and limb_idx + 1 < 4:
        value |= limbs[limb_idx + 1] << (64 - shift)
    return <unsigned int>(value & mask)

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
    return (int((xm * inv_z) % pm), int((ym * inv_z) % pm))


cpdef tuple msm_pippenger_signed_native_cy(
    object points,
    object scalars,
    object a_coeff,
    object d_coeff,
    object p,
    int window_bits = 7,
    bint affine = False,
):
    """
    Variable-base MSM using signed-window Pippenger recoding.

    Signed digits halve the number of nonzero buckets for each window. The
    scalar recoding is done once up front so the high-to-low Pippenger schedule
    can stay branch-light inside the bucket loop.
    """
    cdef Py_ssize_t n = len(points)
    cdef Py_ssize_t i
    cdef int j, bucket_index, window_index
    cdef int max_bits = 0
    cdef int bits
    cdef int base_windows
    cdef int num_windows
    cdef int bucket_count
    cdef int half_bucket_count
    cdef int highest_window = -1
    cdef unsigned int raw_digit
    cdef int digit
    cdef int carry
    cdef TEProjNative *point_arr = NULL
    cdef TEProjNative *neg_point_arr = NULL
    cdef TEProjNative *buckets = NULL
    cdef uint64_t *scalar_limbs = NULL
    cdef int16_t *signed_digits = NULL
    cdef TEProjNative result
    cdef TEProjNative running
    cdef TEProjNative base_point
    cdef bls_scalar_t a_mont, d_mont
    cdef object point
    cdef object scalar_value

    if n != len(scalars):
        raise ValueError("Points and scalars must have same length")
    if n == 0:
        if affine:
            return (0, 1)
        return (0, 1, 1, 0)
    if window_bits < 2 or window_bits > 8:
        raise ValueError("window_bits must be between 2 and 8")

    bucket_count = 1 << window_bits
    half_bucket_count = bucket_count >> 1
    point_arr = <TEProjNative *>malloc(n * sizeof(TEProjNative))
    neg_point_arr = <TEProjNative *>malloc(n * sizeof(TEProjNative))
    scalar_limbs = <uint64_t *>malloc(n * 4 * sizeof(uint64_t))
    if point_arr == NULL or neg_point_arr == NULL or scalar_limbs == NULL:
        if point_arr != NULL:
            free(point_arr)
        if neg_point_arr != NULL:
            free(neg_point_arr)
        if scalar_limbs != NULL:
            free(scalar_limbs)
        raise MemoryError()

    try:
        _scalar_from_py_mont(&a_mont, a_coeff)
        _scalar_from_py_mont(&d_mont, d_coeff)

        for i in range(n):
            point = points[i]
            scalar_value = int(scalars[i])
            if scalar_value < 0:
                scalar_value = -scalar_value
            _scalar_limbs_from_py(&scalar_limbs[i * 4], scalar_value)
            bits = _scalar_limbs_bit_length(&scalar_limbs[i * 4])
            if bits > max_bits:
                max_bits = bits

            _scalar_from_py_mont(&base_point.x, point.x)
            _scalar_from_py_mont(&base_point.y, point.y)
            _scalar_one_mont(&base_point.z)
            bls_scalar_mul_mont(&base_point.t, &base_point.x, &base_point.y)
            if int(scalars[i]) < 0:
                _point_neg_native(&point_arr[i], &base_point)
                _point_copy(&neg_point_arr[i], &base_point)
            else:
                _point_copy(&point_arr[i], &base_point)
                _point_neg_native(&neg_point_arr[i], &base_point)

        if max_bits == 0:
            if affine:
                return (0, 1)
            return (0, 1, 1, 0)

        base_windows = (max_bits + window_bits - 1) // window_bits
        num_windows = base_windows + 1
        signed_digits = <int16_t *>malloc(n * num_windows * sizeof(int16_t))
        buckets = <TEProjNative *>malloc((half_bucket_count + 1) * sizeof(TEProjNative))
        if signed_digits == NULL or buckets == NULL:
            if signed_digits != NULL:
                free(signed_digits)
            if buckets != NULL:
                free(buckets)
            raise MemoryError()

        for i in range(n):
            carry = 0
            for window_index in range(base_windows):
                raw_digit = _scalar_window_bits(&scalar_limbs[i * 4], window_index * window_bits, window_bits)
                digit = <int>raw_digit + carry
                if digit >= half_bucket_count:
                    digit -= bucket_count
                    carry = 1
                else:
                    carry = 0
                signed_digits[i * num_windows + window_index] = <int16_t>digit
                if digit != 0 and window_index > highest_window:
                    highest_window = window_index
            signed_digits[i * num_windows + base_windows] = <int16_t>carry
            if carry != 0 and base_windows > highest_window:
                highest_window = base_windows

        _point_identity(&result)
        for window_index in range(highest_window, -1, -1):
            if window_index != highest_window:
                for j in range(window_bits):
                    _te_double_native(&result, &result, &a_mont)

            for bucket_index in range(1, half_bucket_count + 1):
                _point_identity(&buckets[bucket_index])

            for i in range(n):
                digit = signed_digits[i * num_windows + window_index]
                if digit > 0:
                    _te_add_native(&buckets[digit], &buckets[digit], &point_arr[i], &a_mont, &d_mont)
                elif digit < 0:
                    _te_add_native(&buckets[-digit], &buckets[-digit], &neg_point_arr[i], &a_mont, &d_mont)

            _point_identity(&running)
            for bucket_index in range(half_bucket_count, 0, -1):
                _te_add_native(&running, &running, &buckets[bucket_index], &a_mont, &d_mont)
                _te_add_native(&result, &result, &running, &a_mont, &d_mont)

        if affine:
            return _projective_native_to_affine_tuple(&result)
        return (
            _scalar_to_py_int(&result.x),
            _scalar_to_py_int(&result.y),
            _scalar_to_py_int(&result.z),
            _scalar_to_py_int(&result.t),
        )
    finally:
        if point_arr != NULL:
            free(point_arr)
        if neg_point_arr != NULL:
            free(neg_point_arr)
        if scalar_limbs != NULL:
            free(scalar_limbs)
        if signed_digits != NULL:
            free(signed_digits)
        if buckets != NULL:
            free(buckets)


cpdef object sqrt_mod_bls_scalar_cy(object x):
    """
    Tonelli-Shanks square root for the BLS12-381 scalar field.

    Bandersnatch's base field is this field. Keeping the 2-adic Tonelli loop in
    native field operations avoids the Python big-int loop that dominates
    Elligator2 hash-to-curve.
    """
    cdef object value = int(x) % _BLS_SCALAR_MODULUS_INT
    cdef bls_scalar_t xm, R, t, c, b, temp, one, exp_raw
    cdef int M, i, j

    if value == 0:
        return 0

    _scalar_from_py_mont(&xm, value)
    _scalar_one_mont(&one)

    # p - 1 = Q * 2^32 for the BLS12-381 scalar field.
    _scalar_from_py_raw(
        &exp_raw,
        0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF,
    )
    bls_scalar_exp(&t, &xm, &exp_raw)

    _scalar_from_py_raw(
        &exp_raw,
        0x39F6D3A994CEBEA4199CEC0404D0EC02A9DED2017FFF2DFF80000000,
    )
    bls_scalar_exp(&R, &xm, &exp_raw)

    # First quadratic non-residue is 5; c = 5^Q.
    _scalar_from_py_mont(
        &c,
        0x212D79E5B416B6F0FD56DC8D168D6C0C4024FF270B3E0941B788F500B912F1F,
    )

    M = 32
    while True:
        if _scalar_eq(&t, &one):
            return _scalar_to_py_int(&R)

        i = 1
        bls_scalar_mul_mont(&temp, &t, &t)
        while not _scalar_eq(&temp, &one):
            bls_scalar_mul_mont(&temp, &temp, &temp)
            i += 1
            if i >= M:
                raise ValueError("sqrt_mod_bls_scalar_cy received a non-square")

        b = c
        for j in range(M - i - 1):
            bls_scalar_mul_mont(&b, &b, &b)
        M = i
        bls_scalar_mul_mont(&c, &b, &b)
        bls_scalar_mul_mont(&t, &t, &c)
        bls_scalar_mul_mont(&R, &R, &b)


cpdef tuple scalar_mult_windowed_native_w2_cy(
    object k1, object k2,
    object p1_x, object p1_y, object p1_z, object p1_t,
    object p2_x, object p2_y, object p2_z, object p2_t,
    object a_coeff, object d_coeff, object p,
):
    """
    Compute k1 * P1 + k2 * P2 with a fixed 2-bit window over native
    BLS12-381 scalar-field arithmetic.

    Bandersnatch's base field is the BLS12-381 scalar field, so this avoids the
    gmpy2 object arithmetic in the older Cython kernel while preserving the same
    extended Edwards formulas.
    """
    cdef TEProjNative p1_base
    cdef TEProjNative p2_base
    cdef TEProjNative p1_mults[4]
    cdef TEProjNative p2_mults[4]
    cdef TEProjNative table[4][4]
    cdef TEProjNative R
    cdef bls_scalar_t a_mont, d_mont
    cdef uint64_t k1_limbs[4]
    cdef uint64_t k2_limbs[4]
    cdef int i, j, max_bits, bits1, bits2, num_windows
    cdef unsigned int k1_win, k2_win

    _scalar_from_py_mont(&a_mont, a_coeff)
    _scalar_from_py_mont(&d_mont, d_coeff)
    _point_from_py(&p1_base, p1_x, p1_y, p1_z, p1_t)
    _point_from_py(&p2_base, p2_x, p2_y, p2_z, p2_t)
    _scalar_limbs_from_py(k1_limbs, k1)
    _scalar_limbs_from_py(k2_limbs, k2)

    _point_identity(&p1_mults[0])
    _point_copy(&p1_mults[1], &p1_base)
    _te_add_native(&p1_mults[2], &p1_mults[1], &p1_base, &a_mont, &d_mont)
    _te_add_native(&p1_mults[3], &p1_mults[2], &p1_base, &a_mont, &d_mont)

    _point_identity(&p2_mults[0])
    _point_copy(&p2_mults[1], &p2_base)
    _te_add_native(&p2_mults[2], &p2_mults[1], &p2_base, &a_mont, &d_mont)
    _te_add_native(&p2_mults[3], &p2_mults[2], &p2_base, &a_mont, &d_mont)

    for i in range(4):
        for j in range(4):
            if i == 0:
                _point_copy(&table[i][j], &p2_mults[j])
            elif j == 0:
                _point_copy(&table[i][j], &p1_mults[i])
            else:
                _te_add_native(&table[i][j], &p1_mults[i], &p2_mults[j], &a_mont, &d_mont)

    bits1 = _scalar_limbs_bit_length(k1_limbs)
    bits2 = _scalar_limbs_bit_length(k2_limbs)
    max_bits = bits1 if bits1 >= bits2 else bits2
    if max_bits == 0:
        max_bits = 1
    num_windows = (max_bits + 1) >> 1

    _point_identity(&R)
    for i in range(num_windows - 1, -1, -1):
        _te_double_native(&R, &R, &a_mont)
        _te_double_native(&R, &R, &a_mont)

        k1_win = _scalar_window2(k1_limbs, i << 1)
        k2_win = _scalar_window2(k2_limbs, i << 1)
        if k1_win != 0 or k2_win != 0:
            _te_add_native(&R, &R, &table[k1_win][k2_win], &a_mont, &d_mont)

    return (
        _scalar_to_py_int(&R.x),
        _scalar_to_py_int(&R.y),
        _scalar_to_py_int(&R.z),
        _scalar_to_py_int(&R.t),
    )


cpdef tuple scalar_mult_4_native_w2_cy(
    object k1, object k2, object k3, object k4,
    object p1_x, object p1_y, object p1_z, object p1_t,
    object p2_x, object p2_y, object p2_z, object p2_t,
    object p3_x, object p3_y, object p3_z, object p3_t,
    object p4_x, object p4_y, object p4_z, object p4_t,
    object a_coeff, object d_coeff, object p,
):
    """
    Compute k1*P1 + k2*P2 + k3*P3 + k4*P4 with two 2-point native
    lookup tables and a 2-bit window.
    """
    cdef TEProjNative p1_base
    cdef TEProjNative p2_base
    cdef TEProjNative p3_base
    cdef TEProjNative p4_base
    cdef TEProjNative p1_mults[4]
    cdef TEProjNative p2_mults[4]
    cdef TEProjNative p3_mults[4]
    cdef TEProjNative p4_mults[4]
    cdef TEProjNative table12[4][4]
    cdef TEProjNative table34[4][4]
    cdef TEProjNative R
    cdef bls_scalar_t a_mont, d_mont
    cdef uint64_t k1_limbs[4]
    cdef uint64_t k2_limbs[4]
    cdef uint64_t k3_limbs[4]
    cdef uint64_t k4_limbs[4]
    cdef int i, j, max_bits, bits
    cdef int num_windows
    cdef unsigned int k1_win, k2_win, k3_win, k4_win

    _scalar_from_py_mont(&a_mont, a_coeff)
    _scalar_from_py_mont(&d_mont, d_coeff)
    _point_from_py(&p1_base, p1_x, p1_y, p1_z, p1_t)
    _point_from_py(&p2_base, p2_x, p2_y, p2_z, p2_t)
    _point_from_py(&p3_base, p3_x, p3_y, p3_z, p3_t)
    _point_from_py(&p4_base, p4_x, p4_y, p4_z, p4_t)
    _scalar_limbs_from_py(k1_limbs, k1)
    _scalar_limbs_from_py(k2_limbs, k2)
    _scalar_limbs_from_py(k3_limbs, k3)
    _scalar_limbs_from_py(k4_limbs, k4)

    _point_identity(&p1_mults[0])
    _point_copy(&p1_mults[1], &p1_base)
    _te_add_native(&p1_mults[2], &p1_mults[1], &p1_base, &a_mont, &d_mont)
    _te_add_native(&p1_mults[3], &p1_mults[2], &p1_base, &a_mont, &d_mont)

    _point_identity(&p2_mults[0])
    _point_copy(&p2_mults[1], &p2_base)
    _te_add_native(&p2_mults[2], &p2_mults[1], &p2_base, &a_mont, &d_mont)
    _te_add_native(&p2_mults[3], &p2_mults[2], &p2_base, &a_mont, &d_mont)

    _point_identity(&p3_mults[0])
    _point_copy(&p3_mults[1], &p3_base)
    _te_add_native(&p3_mults[2], &p3_mults[1], &p3_base, &a_mont, &d_mont)
    _te_add_native(&p3_mults[3], &p3_mults[2], &p3_base, &a_mont, &d_mont)

    _point_identity(&p4_mults[0])
    _point_copy(&p4_mults[1], &p4_base)
    _te_add_native(&p4_mults[2], &p4_mults[1], &p4_base, &a_mont, &d_mont)
    _te_add_native(&p4_mults[3], &p4_mults[2], &p4_base, &a_mont, &d_mont)

    for i in range(4):
        for j in range(4):
            if i == 0:
                _point_copy(&table12[i][j], &p2_mults[j])
                _point_copy(&table34[i][j], &p4_mults[j])
            elif j == 0:
                _point_copy(&table12[i][j], &p1_mults[i])
                _point_copy(&table34[i][j], &p3_mults[i])
            else:
                _te_add_native(&table12[i][j], &p1_mults[i], &p2_mults[j], &a_mont, &d_mont)
                _te_add_native(&table34[i][j], &p3_mults[i], &p4_mults[j], &a_mont, &d_mont)

    max_bits = _scalar_limbs_bit_length(k1_limbs)
    bits = _scalar_limbs_bit_length(k2_limbs)
    if bits > max_bits:
        max_bits = bits
    bits = _scalar_limbs_bit_length(k3_limbs)
    if bits > max_bits:
        max_bits = bits
    bits = _scalar_limbs_bit_length(k4_limbs)
    if bits > max_bits:
        max_bits = bits
    if max_bits == 0:
        max_bits = 1
    num_windows = (max_bits + 1) >> 1

    _point_identity(&R)
    for i in range(num_windows - 1, -1, -1):
        _te_double_native(&R, &R, &a_mont)
        _te_double_native(&R, &R, &a_mont)

        k1_win = _scalar_window2(k1_limbs, i << 1)
        k2_win = _scalar_window2(k2_limbs, i << 1)
        k3_win = _scalar_window2(k3_limbs, i << 1)
        k4_win = _scalar_window2(k4_limbs, i << 1)

        if k1_win != 0 or k2_win != 0:
            _te_add_native(&R, &R, &table12[k1_win][k2_win], &a_mont, &d_mont)
        if k3_win != 0 or k4_win != 0:
            _te_add_native(&R, &R, &table34[k3_win][k4_win], &a_mont, &d_mont)

    return (
        _scalar_to_py_int(&R.x),
        _scalar_to_py_int(&R.y),
        _scalar_to_py_int(&R.z),
        _scalar_to_py_int(&R.t),
    )


cpdef tuple scalar_mult_6_native_w2_cy(
    object k1, object k2, object k3, object k4, object k5, object k6,
    object p1_x, object p1_y, object p1_z, object p1_t,
    object p2_x, object p2_y, object p2_z, object p2_t,
    object p3_x, object p3_y, object p3_z, object p3_t,
    object p4_x, object p4_y, object p4_z, object p4_t,
    object p5_x, object p5_y, object p5_z, object p5_t,
    object p6_x, object p6_y, object p6_z, object p6_t,
    object a_coeff, object d_coeff, object p,
):
    """
    Compute a 6-point MSM as three paired 2-bit lookup tables.

    This is intended for GLV-split 3-point MSMs: each original scalar is split
    into two roughly half-width scalars and paired with its endomorphism point.
    """
    cdef TEProjNative p1_base
    cdef TEProjNative p2_base
    cdef TEProjNative p3_base
    cdef TEProjNative p4_base
    cdef TEProjNative p5_base
    cdef TEProjNative p6_base
    cdef TEProjNative p1_mults[4]
    cdef TEProjNative p2_mults[4]
    cdef TEProjNative p3_mults[4]
    cdef TEProjNative p4_mults[4]
    cdef TEProjNative p5_mults[4]
    cdef TEProjNative p6_mults[4]
    cdef TEProjNative table12[4][4]
    cdef TEProjNative table34[4][4]
    cdef TEProjNative table56[4][4]
    cdef TEProjNative R
    cdef bls_scalar_t a_mont, d_mont
    cdef uint64_t k1_limbs[4]
    cdef uint64_t k2_limbs[4]
    cdef uint64_t k3_limbs[4]
    cdef uint64_t k4_limbs[4]
    cdef uint64_t k5_limbs[4]
    cdef uint64_t k6_limbs[4]
    cdef int i, j, max_bits, bits
    cdef int num_windows
    cdef unsigned int k1_win, k2_win, k3_win, k4_win, k5_win, k6_win

    _scalar_from_py_mont(&a_mont, a_coeff)
    _scalar_from_py_mont(&d_mont, d_coeff)
    _point_from_py(&p1_base, p1_x, p1_y, p1_z, p1_t)
    _point_from_py(&p2_base, p2_x, p2_y, p2_z, p2_t)
    _point_from_py(&p3_base, p3_x, p3_y, p3_z, p3_t)
    _point_from_py(&p4_base, p4_x, p4_y, p4_z, p4_t)
    _point_from_py(&p5_base, p5_x, p5_y, p5_z, p5_t)
    _point_from_py(&p6_base, p6_x, p6_y, p6_z, p6_t)
    _scalar_limbs_from_py(k1_limbs, k1)
    _scalar_limbs_from_py(k2_limbs, k2)
    _scalar_limbs_from_py(k3_limbs, k3)
    _scalar_limbs_from_py(k4_limbs, k4)
    _scalar_limbs_from_py(k5_limbs, k5)
    _scalar_limbs_from_py(k6_limbs, k6)

    _point_identity(&p1_mults[0])
    _point_copy(&p1_mults[1], &p1_base)
    _te_add_native(&p1_mults[2], &p1_mults[1], &p1_base, &a_mont, &d_mont)
    _te_add_native(&p1_mults[3], &p1_mults[2], &p1_base, &a_mont, &d_mont)

    _point_identity(&p2_mults[0])
    _point_copy(&p2_mults[1], &p2_base)
    _te_add_native(&p2_mults[2], &p2_mults[1], &p2_base, &a_mont, &d_mont)
    _te_add_native(&p2_mults[3], &p2_mults[2], &p2_base, &a_mont, &d_mont)

    _point_identity(&p3_mults[0])
    _point_copy(&p3_mults[1], &p3_base)
    _te_add_native(&p3_mults[2], &p3_mults[1], &p3_base, &a_mont, &d_mont)
    _te_add_native(&p3_mults[3], &p3_mults[2], &p3_base, &a_mont, &d_mont)

    _point_identity(&p4_mults[0])
    _point_copy(&p4_mults[1], &p4_base)
    _te_add_native(&p4_mults[2], &p4_mults[1], &p4_base, &a_mont, &d_mont)
    _te_add_native(&p4_mults[3], &p4_mults[2], &p4_base, &a_mont, &d_mont)

    _point_identity(&p5_mults[0])
    _point_copy(&p5_mults[1], &p5_base)
    _te_add_native(&p5_mults[2], &p5_mults[1], &p5_base, &a_mont, &d_mont)
    _te_add_native(&p5_mults[3], &p5_mults[2], &p5_base, &a_mont, &d_mont)

    _point_identity(&p6_mults[0])
    _point_copy(&p6_mults[1], &p6_base)
    _te_add_native(&p6_mults[2], &p6_mults[1], &p6_base, &a_mont, &d_mont)
    _te_add_native(&p6_mults[3], &p6_mults[2], &p6_base, &a_mont, &d_mont)

    for i in range(4):
        for j in range(4):
            if i == 0:
                _point_copy(&table12[i][j], &p2_mults[j])
                _point_copy(&table34[i][j], &p4_mults[j])
                _point_copy(&table56[i][j], &p6_mults[j])
            elif j == 0:
                _point_copy(&table12[i][j], &p1_mults[i])
                _point_copy(&table34[i][j], &p3_mults[i])
                _point_copy(&table56[i][j], &p5_mults[i])
            else:
                _te_add_native(&table12[i][j], &p1_mults[i], &p2_mults[j], &a_mont, &d_mont)
                _te_add_native(&table34[i][j], &p3_mults[i], &p4_mults[j], &a_mont, &d_mont)
                _te_add_native(&table56[i][j], &p5_mults[i], &p6_mults[j], &a_mont, &d_mont)

    max_bits = _scalar_limbs_bit_length(k1_limbs)
    bits = _scalar_limbs_bit_length(k2_limbs)
    if bits > max_bits:
        max_bits = bits
    bits = _scalar_limbs_bit_length(k3_limbs)
    if bits > max_bits:
        max_bits = bits
    bits = _scalar_limbs_bit_length(k4_limbs)
    if bits > max_bits:
        max_bits = bits
    bits = _scalar_limbs_bit_length(k5_limbs)
    if bits > max_bits:
        max_bits = bits
    bits = _scalar_limbs_bit_length(k6_limbs)
    if bits > max_bits:
        max_bits = bits
    if max_bits == 0:
        max_bits = 1
    num_windows = (max_bits + 1) >> 1

    _point_identity(&R)
    for i in range(num_windows - 1, -1, -1):
        _te_double_native(&R, &R, &a_mont)
        _te_double_native(&R, &R, &a_mont)

        k1_win = _scalar_window2(k1_limbs, i << 1)
        k2_win = _scalar_window2(k2_limbs, i << 1)
        k3_win = _scalar_window2(k3_limbs, i << 1)
        k4_win = _scalar_window2(k4_limbs, i << 1)
        k5_win = _scalar_window2(k5_limbs, i << 1)
        k6_win = _scalar_window2(k6_limbs, i << 1)

        if k1_win != 0 or k2_win != 0:
            _te_add_native(&R, &R, &table12[k1_win][k2_win], &a_mont, &d_mont)
        if k3_win != 0 or k4_win != 0:
            _te_add_native(&R, &R, &table34[k3_win][k4_win], &a_mont, &d_mont)
        if k5_win != 0 or k6_win != 0:
            _te_add_native(&R, &R, &table56[k5_win][k6_win], &a_mont, &d_mont)

    return (
        _scalar_to_py_int(&R.x),
        _scalar_to_py_int(&R.y),
        _scalar_to_py_int(&R.z),
        _scalar_to_py_int(&R.t),
    )
