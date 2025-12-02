"""
Setup script for Cython extensions.

Usage:
    python scripts/setup_cython.py build_ext --inplace
"""

from Cython.Build import cythonize
from setuptools import Extension, setup

extensions = [
    Extension(
        "dot_ring.curve.field_arithmetic",
        ["dot_ring/curve/field_arithmetic.pyx"],
        extra_compile_args=["-O3", "-ffast-math", "-flto", "-march=native"],
    ),
    Extension(
        "dot_ring.curve.fast_math",
        ["dot_ring/curve/fast_math.pyx"],
        extra_compile_args=["-O3", "-ffast-math", "-flto", "-march=native"],
    ),
    Extension(
        "dot_ring.ring_proof.polynomial.ntt",
        ["dot_ring/ring_proof/polynomial/ntt.pyx"],
        extra_compile_args=["-O3", "-ffast-math", "-flto", "-march=native"],
    ),
    Extension(
        "dot_ring.curve.native_field.scalar",
        ["dot_ring/curve/native_field/scalar.pyx"],
        extra_compile_args=["-O3", "-ffast-math", "-flto", "-march=native"],
    ),
]

setup(
    name="dot_ring_cython",
    packages=["dot_ring", "dot_ring.curve", "dot_ring.ring_proof.polynomial"],
    ext_modules=cythonize(
        extensions,
        compiler_directives={
            "language_level": "3",
            "boundscheck": False,
            "wraparound": False,
            "cdivision": True,
        },
        annotate=True,
    ),
)
