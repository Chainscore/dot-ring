# cython: language_level=3
# cython: boundscheck=False
# cython: wraparound=False

from libc.stdint cimport uint64_t, uint8_t
from cpython.object cimport Py_EQ, Py_NE

cimport cython

@cython.final
@cython.freelist(100)
cdef class Scalar:
    def __cinit__(self, object value=None):
        if value is None:
            # Initialize to 0
            self.val.val[0] = 0
            self.val.val[1] = 0
            self.val.val[2] = 0
            self.val.val[3] = 0
        elif isinstance(value, int):
            value = value % 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
            if value < 0x10000000000000000:
                bls_scalar_from_uint64(&self.val, value)
                bls_scalar_to_mont(&self.val, &self.val)
            else:
                b = value.to_bytes(32, 'little')
                bls_scalar_from_bytes(&self.val, <const uint8_t*>b)
                bls_scalar_to_mont(&self.val, &self.val)
        elif isinstance(value, Scalar):
            self.val = (<Scalar>value).val
            
    @staticmethod
    cdef Scalar from_native(bls_scalar_t val):
        cdef Scalar res = Scalar.__new__(Scalar)
        res.val = val
        return res
        
    def to_int(self):
        cdef bls_scalar_t tmp
        cdef uint8_t b[32]
        bls_scalar_from_mont(&tmp, &self.val)
        bls_scalar_to_bytes(b, &tmp)
        return int.from_bytes(b[:32], 'little')

    def to_bytes(self, length=32, byteorder='little', signed_=False):
        if length != 32 or byteorder != 'little' or signed_:
            return self.to_int().to_bytes(length, byteorder, signed=signed_)
        
        cdef bls_scalar_t tmp
        cdef uint8_t b[32]
        bls_scalar_from_mont(&tmp, &self.val)
        bls_scalar_to_bytes(b, &tmp)
        return bytes(b[:32])

    def bit_length(self):
        return self.to_int().bit_length()

    def __int__(self):
        return self.to_int()

    def __add__(self, other):
        if not isinstance(other, Scalar):
            other = Scalar(other)
        cdef Scalar res = Scalar.__new__(Scalar)
        bls_scalar_add(&res.val, &self.val, &(<Scalar>other).val)
        return res

    def __radd__(self, other):
        return self + other

    def __sub__(self, other):
        if not isinstance(other, Scalar):
            other = Scalar(other)
        cdef Scalar res = Scalar.__new__(Scalar)
        bls_scalar_sub(&res.val, &self.val, &(<Scalar>other).val)
        return res

    def __rsub__(self, other):
        return Scalar(other) - self

    def __mul__(self, other):
        if not isinstance(other, Scalar):
            other = Scalar(other)
        cdef Scalar res = Scalar.__new__(Scalar)
        bls_scalar_mul_mont(&res.val, &self.val, &(<Scalar>other).val)
        return res

    def __rmul__(self, other):
        return self * other
        
    def __pow__(self, exponent: int, modulus=None):
        cdef Scalar res = Scalar.__new__(Scalar)
        cdef uint8_t exp_bytes[32]
        cdef bls_scalar_t exp_raw
        cdef Scalar inv_base
        
        if exponent < 0:
            # Inverse
            inv_base = Scalar.__new__(Scalar)
            bls_scalar_inv(&inv_base.val, &self.val)
            if exponent == -1:
                return inv_base
            exponent = -exponent
            # Now pow(inv_base, exponent)
            # Convert exponent to bytes then to bls_scalar_t
            b = exponent.to_bytes(32, 'little')
            for i in range(32):
                exp_bytes[i] = b[i]
            bls_scalar_from_bytes(&exp_raw, exp_bytes)
            bls_scalar_exp(&res.val, &inv_base.val, &exp_raw)
        else:
            # Convert exponent to bytes then to bls_scalar_t
            b = exponent.to_bytes(32, 'little')
            for i in range(32):
                exp_bytes[i] = b[i]
            bls_scalar_from_bytes(&exp_raw, exp_bytes)
            bls_scalar_exp(&res.val, &self.val, &exp_raw)

        return res

    def __neg__(self):
        cdef Scalar res = Scalar.__new__(Scalar)
        cdef bls_scalar_t zero
        zero.val[0] = 0; zero.val[1] = 0; zero.val[2] = 0; zero.val[3] = 0
        bls_scalar_sub(&res.val, &zero, &self.val)
        return res
        
    def __eq__(self, other):
        if isinstance(other, Scalar):
            # Compare raw values (assuming canonical reduction)
            # Since we are in Montgomery form and always reduced mod P, 
            # byte comparison of val is sufficient.
            for i in range(4):
                if self.val.val[i] != (<Scalar>other).val.val[i]:
                    return False
            return True
        elif isinstance(other, int):
            return self.to_int() == other
        return NotImplemented

    def __lt__(self, other):
        if isinstance(other, Scalar):
            return self.to_int() < (<Scalar>other).to_int()
        return self.to_int() < other

    def __le__(self, other):
        if isinstance(other, Scalar):
            return self.to_int() <= (<Scalar>other).to_int()
        return self.to_int() <= other

    def __gt__(self, other):
        if isinstance(other, Scalar):
            return self.to_int() > (<Scalar>other).to_int()
        return self.to_int() > other

    def __ge__(self, other):
        if isinstance(other, Scalar):
            return self.to_int() >= (<Scalar>other).to_int()
        return self.to_int() >= other

    def __mod__(self, other):
        return self.to_int() % other

    def __repr__(self):
        return f"Scalar({self.to_int()})"
