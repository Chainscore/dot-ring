# cython: language_level=3
# cython: boundscheck=False
# cython: wraparound=False
# cython: cdivision=True
# cython: initializedcheck=False
from libc.stdlib cimport malloc, free
from libc.stdint cimport uint8_t
from dot_ring.curve.native_field.scalar cimport (
    Scalar,
    bls_scalar_from_mont,
    bls_scalar_mul_mont,
    bls_scalar_t,
    bls_scalar_ntt_round,
    bls_scalar_to_bytes,
)

cdef extern from "stdlib.h":
    int posix_memalign(void **memptr, size_t alignment, size_t size)


cdef inline object _scalar_to_int(const bls_scalar_t *value):
    cdef bls_scalar_t raw
    cdef uint8_t b[32]
    bls_scalar_from_mont(&raw, value)
    bls_scalar_to_bytes(b, &raw)
    return int.from_bytes((<char *>b)[:32], "little")


cdef class BlsScalarNTTPlan:
    cdef Py_ssize_t n
    cdef Py_ssize_t stages
    cdef Py_ssize_t *rev_c
    cdef bls_scalar_t *twiddles_c
    cdef Py_ssize_t *twiddle_offsets

    def __cinit__(self, list twiddles, list rev):
        cdef:
            Py_ssize_t i, stage, offset, total_twiddles, expected_stages, m
            list stage_twiddles
            object val
            Scalar s

        self.n = len(rev)
        self.stages = len(twiddles)
        self.rev_c = NULL
        self.twiddles_c = NULL
        self.twiddle_offsets = NULL

        if self.n < 2 or self.n & (self.n - 1):
            raise ValueError(f"native NTT plan size must be a power of two >= 2, got {self.n}")

        expected_stages = self.n.bit_length() - 1
        if self.stages != expected_stages:
            raise ValueError(f"native NTT plan expected {expected_stages} twiddle stages, got {self.stages}")

        for val in rev:
            if val < 0 or val >= self.n:
                raise ValueError(f"bit-reverse index {val} is outside plan size {self.n}")

        m = 2
        for stage in range(self.stages):
            if len(twiddles[stage]) != (m >> 1):
                raise ValueError(f"twiddle stage {stage} has invalid length {len(twiddles[stage])}; expected {m >> 1}")
            m <<= 1

        self.rev_c = <Py_ssize_t *>malloc(self.n * sizeof(Py_ssize_t))
        self.twiddle_offsets = <Py_ssize_t *>malloc(self.stages * sizeof(Py_ssize_t))
        if not self.rev_c or not self.twiddle_offsets:
            raise MemoryError()

        for i in range(self.n):
            self.rev_c[i] = <Py_ssize_t>rev[i]

        total_twiddles = 0
        for stage in range(self.stages):
            stage_twiddles = twiddles[stage]
            self.twiddle_offsets[stage] = total_twiddles
            total_twiddles += len(stage_twiddles)

        self.twiddles_c = <bls_scalar_t *>malloc(total_twiddles * sizeof(bls_scalar_t))
        if not self.twiddles_c:
            raise MemoryError()

        offset = 0
        for stage in range(self.stages):
            stage_twiddles = twiddles[stage]
            for i in range(len(stage_twiddles)):
                val = stage_twiddles[i]
                if isinstance(val, Scalar):
                    self.twiddles_c[offset + i] = (<Scalar>val).val
                else:
                    s = Scalar(val)
                    self.twiddles_c[offset + i] = s.val
            offset += len(stage_twiddles)

    def __dealloc__(self):
        if self.rev_c:
            free(self.rev_c)
        if self.twiddles_c:
            free(self.twiddles_c)
        if self.twiddle_offsets:
            free(self.twiddle_offsets)

    def transform(self, list coeffs):
        """Run an in-place NTT over the BLS12-381 scalar field."""
        if len(coeffs) <= 1:
            return
        self._transform_core(coeffs, None, False)

    def transform_scaled(self, list coeffs, object scale):
        """Run an in-place NTT over the BLS12-381 scalar field and scale each output."""
        if len(coeffs) <= 1:
            return
        self._transform_core(coeffs, scale, True)

    cdef void _transform_core(self, list coeffs, object scale, bint apply_scale) except *:
        cdef:
            Py_ssize_t n = len(coeffs)
            Py_ssize_t i, stage, m
            bls_scalar_t *coeffs_c
            bls_scalar_t scale_s
            bls_scalar_t scaled
            object val
            Scalar s
            void *ptr = NULL

        if n != self.n:
            raise ValueError(f"coefficient length {n} does not match native NTT plan size {self.n}")

        if apply_scale:
            if isinstance(scale, Scalar):
                scale_s = (<Scalar>scale).val
            else:
                scale_s = Scalar(scale).val

        if posix_memalign(&ptr, 32, n * sizeof(bls_scalar_t)) != 0:
            raise MemoryError()
        coeffs_c = <bls_scalar_t *>ptr

        try:
            for i in range(n):
                val = coeffs[self.rev_c[i]]
                if isinstance(val, Scalar):
                    coeffs_c[i] = (<Scalar>val).val
                else:
                    coeffs_c[i] = Scalar(val).val
            
            stage = 0
            m = 2
            while m <= n:
                bls_scalar_ntt_round(coeffs_c, n, &self.twiddles_c[self.twiddle_offsets[stage]], m)
                m <<= 1
                stage += 1
            
            for i in range(n):
                if apply_scale:
                    bls_scalar_mul_mont(&scaled, &coeffs_c[i], &scale_s)
                    coeffs[i] = _scalar_to_int(&scaled)
                else:
                    coeffs[i] = _scalar_to_int(&coeffs_c[i])
                
        finally:
            free(coeffs_c)
