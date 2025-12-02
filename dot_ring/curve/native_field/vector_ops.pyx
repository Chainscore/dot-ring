# cython: language_level=3
# cython: boundscheck=False
# cython: wraparound=False

from libc.stdint cimport uint64_t, uint8_t
from libc.stdlib cimport malloc, free
from dot_ring.curve.native_field.scalar cimport Scalar, bls_scalar_t, bls_scalar_vec_add, bls_scalar_vec_sub, bls_scalar_vec_mul, bls_scalar_vec_mul_scalar, bls_scalar_vec_add_scalar, bls_scalar_vec_sub_scalar, bls_scalar_sub

cdef class VectorOps:
    pass

def vect_add(object a, object b, object prime):
    cdef int n, i
    cdef bls_scalar_t *a_ptr
    cdef bls_scalar_t *b_ptr
    cdef bls_scalar_t *res_ptr
    cdef list res_list
    cdef Scalar s_res
    cdef int is_a_list = isinstance(a, list)
    cdef int is_b_list = isinstance(b, list)
    cdef bls_scalar_t scalar_b
    cdef bls_scalar_t stack_a[256]
    cdef bls_scalar_t stack_b[256]
    cdef bls_scalar_t stack_res[256]
    cdef int use_heap = 0

    if is_a_list and is_b_list:
        n = len(a)
        if len(b) != n:
            raise ValueError("Vector lengths must match")
        
        if n <= 256:
            a_ptr = stack_a
            b_ptr = stack_b
            res_ptr = stack_res
        else:
            use_heap = 1
            a_ptr = <bls_scalar_t *>malloc(n * sizeof(bls_scalar_t))
            b_ptr = <bls_scalar_t *>malloc(n * sizeof(bls_scalar_t))
            res_ptr = <bls_scalar_t *>malloc(n * sizeof(bls_scalar_t))
            
            if not a_ptr or not b_ptr or not res_ptr:
                if a_ptr: free(a_ptr)
                if b_ptr: free(b_ptr)
                if res_ptr: free(res_ptr)
                raise MemoryError()

        try:
            # Unbox inputs
            for i in range(n):
                val_a = a[i]
                if isinstance(val_a, Scalar):
                    a_ptr[i] = (<Scalar>val_a).val
                else:
                    a_ptr[i] = Scalar(val_a).val
                
                val_b = b[i]
                if isinstance(val_b, Scalar):
                    b_ptr[i] = (<Scalar>val_b).val
                else:
                    b_ptr[i] = Scalar(val_b).val
            
            # Call C batch function
            bls_scalar_vec_add(res_ptr, a_ptr, b_ptr, n)
            
            # Box results
            res_list = [None] * n
            for i in range(n):
                s_res = Scalar.__new__(Scalar)
                s_res.val = res_ptr[i]
                res_list[i] = s_res
            return res_list
        finally:
            if use_heap:
                free(a_ptr)
                free(b_ptr)
                free(res_ptr)

    elif is_a_list and not is_b_list:
        # Vector + Scalar
        n = len(a)
        if n <= 256:
            a_ptr = stack_a
            res_ptr = stack_res
        else:
            use_heap = 1
            a_ptr = <bls_scalar_t *>malloc(n * sizeof(bls_scalar_t))
            res_ptr = <bls_scalar_t *>malloc(n * sizeof(bls_scalar_t))
            
            if not a_ptr or not res_ptr:
                if a_ptr: free(a_ptr)
                if res_ptr: free(res_ptr)
                raise MemoryError()
            
        try:
            for i in range(n):
                val_a = a[i]
                if isinstance(val_a, Scalar):
                    a_ptr[i] = (<Scalar>val_a).val
                else:
                    a_ptr[i] = Scalar(val_a).val
            
            if isinstance(b, Scalar):
                scalar_b = (<Scalar>b).val
            else:
                scalar_b = Scalar(b).val
                
            bls_scalar_vec_add_scalar(res_ptr, a_ptr, &scalar_b, n)
            
            res_list = [None] * n
            for i in range(n):
                s_res = Scalar.__new__(Scalar)
                s_res.val = res_ptr[i]
                res_list[i] = s_res
            return res_list
        finally:
            if use_heap:
                free(a_ptr)
                free(res_ptr)

    elif not is_a_list and is_b_list:
        return vect_add(b, a, prime)

    return NotImplemented

def vect_sub(object a, object b, object prime):
    cdef int n, i
    cdef bls_scalar_t *a_ptr
    cdef bls_scalar_t *b_ptr
    cdef bls_scalar_t *res_ptr
    cdef list res_list
    cdef Scalar s_res
    cdef int is_a_list = isinstance(a, list)
    cdef int is_b_list = isinstance(b, list)
    cdef bls_scalar_t scalar_b

    if is_a_list and is_b_list:
        n = len(a)
        if len(b) != n:
            raise ValueError("Vector lengths must match")
        
        a_ptr = <bls_scalar_t *>malloc(n * sizeof(bls_scalar_t))
        b_ptr = <bls_scalar_t *>malloc(n * sizeof(bls_scalar_t))
        res_ptr = <bls_scalar_t *>malloc(n * sizeof(bls_scalar_t))
        
        if not a_ptr or not b_ptr or not res_ptr:
            if a_ptr: free(a_ptr)
            if b_ptr: free(b_ptr)
            if res_ptr: free(res_ptr)
            raise MemoryError()

        try:
            for i in range(n):
                val_a = a[i]
                if isinstance(val_a, Scalar):
                    a_ptr[i] = (<Scalar>val_a).val
                else:
                    a_ptr[i] = Scalar(val_a).val
                
                val_b = b[i]
                if isinstance(val_b, Scalar):
                    b_ptr[i] = (<Scalar>val_b).val
                else:
                    b_ptr[i] = Scalar(val_b).val
            
            bls_scalar_vec_sub(res_ptr, a_ptr, b_ptr, n)
            
            res_list = [None] * n
            for i in range(n):
                s_res = Scalar.__new__(Scalar)
                s_res.val = res_ptr[i]
                res_list[i] = s_res
            return res_list
        finally:
            free(a_ptr)
            free(b_ptr)
            free(res_ptr)

    elif is_a_list and not is_b_list:
        # Vector - Scalar
        n = len(a)
        a_ptr = <bls_scalar_t *>malloc(n * sizeof(bls_scalar_t))
        res_ptr = <bls_scalar_t *>malloc(n * sizeof(bls_scalar_t))
        
        if not a_ptr or not res_ptr:
            if a_ptr: free(a_ptr)
            if res_ptr: free(res_ptr)
            raise MemoryError()
            
        try:
            for i in range(n):
                val_a = a[i]
                if isinstance(val_a, Scalar):
                    a_ptr[i] = (<Scalar>val_a).val
                else:
                    a_ptr[i] = Scalar(val_a).val
            
            if isinstance(b, Scalar):
                scalar_b = (<Scalar>b).val
            else:
                scalar_b = Scalar(b).val
                
            bls_scalar_vec_sub_scalar(res_ptr, a_ptr, &scalar_b, n)
            
            res_list = [None] * n
            for i in range(n):
                s_res = Scalar.__new__(Scalar)
                s_res.val = res_ptr[i]
                res_list[i] = s_res
            return res_list
        finally:
            free(a_ptr)
            free(res_ptr)

    elif not is_a_list and is_b_list:
        # Scalar - Vector
        n = len(b)
        b_ptr = <bls_scalar_t *>malloc(n * sizeof(bls_scalar_t))
        res_ptr = <bls_scalar_t *>malloc(n * sizeof(bls_scalar_t))
        
        if not b_ptr or not res_ptr:
            if b_ptr: free(b_ptr)
            if res_ptr: free(res_ptr)
            raise MemoryError()
            
        try:
            for i in range(n):
                val_b = b[i]
                if isinstance(val_b, Scalar):
                    b_ptr[i] = (<Scalar>val_b).val
                else:
                    b_ptr[i] = Scalar(val_b).val
            
            if isinstance(a, Scalar):
                scalar_b = (<Scalar>a).val
            else:
                scalar_b = Scalar(a).val
                
            # We need scalar - vector[i]
            # bls_scalar_vec_sub_scalar does vector[i] - scalar
            # So we iterate manually or add a C function.
            # Let's iterate manually here for simplicity as we don't have the C function exposed yet.
            # Actually, bls_scalar_sub is exposed.
            for i in range(n):
                bls_scalar_sub(&res_ptr[i], &scalar_b, &b_ptr[i])
            
            res_list = [None] * n
            for i in range(n):
                s_res = Scalar.__new__(Scalar)
                s_res.val = res_ptr[i]
                res_list[i] = s_res
            return res_list
        finally:
            free(b_ptr)
            free(res_ptr)
    
    return NotImplemented

def vect_mul(object a, object b, object prime):
    cdef int n, i
    cdef bls_scalar_t *a_ptr
    cdef bls_scalar_t *b_ptr
    cdef bls_scalar_t *res_ptr
    cdef list res_list
    cdef Scalar s_res
    cdef int is_a_list = isinstance(a, list)
    cdef int is_b_list = isinstance(b, list)
    cdef bls_scalar_t scalar_b
    cdef bls_scalar_t stack_a[256]
    cdef bls_scalar_t stack_b[256]
    cdef bls_scalar_t stack_res[256]
    cdef int use_heap = 0

    if is_a_list and is_b_list:
        n = len(a)
        if len(b) != n:
            raise ValueError("Vector lengths must match")
        
        if n <= 256:
            a_ptr = stack_a
            b_ptr = stack_b
            res_ptr = stack_res
        else:
            use_heap = 1
            a_ptr = <bls_scalar_t *>malloc(n * sizeof(bls_scalar_t))
            b_ptr = <bls_scalar_t *>malloc(n * sizeof(bls_scalar_t))
            res_ptr = <bls_scalar_t *>malloc(n * sizeof(bls_scalar_t))
            
            if not a_ptr or not b_ptr or not res_ptr:
                if a_ptr: free(a_ptr)
                if b_ptr: free(b_ptr)
                if res_ptr: free(res_ptr)
                raise MemoryError()

        try:
            for i in range(n):
                val_a = a[i]
                if isinstance(val_a, Scalar):
                    a_ptr[i] = (<Scalar>val_a).val
                else:
                    a_ptr[i] = Scalar(val_a).val
                
                val_b = b[i]
                if isinstance(val_b, Scalar):
                    b_ptr[i] = (<Scalar>val_b).val
                else:
                    b_ptr[i] = Scalar(val_b).val
            
            bls_scalar_vec_mul(res_ptr, a_ptr, b_ptr, n)
            
            res_list = [None] * n
            for i in range(n):
                s_res = Scalar.__new__(Scalar)
                s_res.val = res_ptr[i]
                res_list[i] = s_res
            return res_list
        finally:
            if use_heap:
                free(a_ptr)
                free(b_ptr)
                free(res_ptr)

    elif is_a_list and not is_b_list:
        # Vector * Scalar
        n = len(a)
        if n <= 256:
            a_ptr = stack_a
            res_ptr = stack_res
        else:
            use_heap = 1
            a_ptr = <bls_scalar_t *>malloc(n * sizeof(bls_scalar_t))
            res_ptr = <bls_scalar_t *>malloc(n * sizeof(bls_scalar_t))
            
            if not a_ptr or not res_ptr:
                if a_ptr: free(a_ptr)
                if res_ptr: free(res_ptr)
                raise MemoryError()
            
        try:
            for i in range(n):
                val_a = a[i]
                if isinstance(val_a, Scalar):
                    a_ptr[i] = (<Scalar>val_a).val
                else:
                    a_ptr[i] = Scalar(val_a).val
            
            if isinstance(b, Scalar):
                scalar_b = (<Scalar>b).val
            else:
                scalar_b = Scalar(b).val
                
            bls_scalar_vec_mul_scalar(res_ptr, a_ptr, &scalar_b, n)
            
            res_list = [None] * n
            for i in range(n):
                s_res = Scalar.__new__(Scalar)
                s_res.val = res_ptr[i]
                res_list[i] = s_res
            return res_list
        finally:
            if use_heap:
                free(a_ptr)
                free(res_ptr)

    elif not is_a_list and is_b_list:
        return vect_mul(b, a, prime)
        
    return NotImplemented


def vect_scalar_mul(object vec, object scalar, object mod=None):
    """
    Multiply each element in the vector by the scalar.
    Same as vect_mul(vec, scalar, mod) but explicit name.
    """
    return vect_mul(vec, scalar, mod)
