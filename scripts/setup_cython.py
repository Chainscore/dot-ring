"""
Setup script for Cython extensions.

Usage:
    python scripts/setup_cython.py build_ext --inplace
"""

import sys
from pathlib import Path

from Cython.Build import cythonize
from setuptools import setup

# Add project root to sys.path
sys.path.append(str(Path(__file__).parent.parent))

from setup import cython_extensions

setup(
    name="dot_ring_cython",
    packages=["dot_ring", "dot_ring.curve", "dot_ring.ring_proof.polynomial"],
    ext_modules=cythonize(
        cython_extensions,
        compiler_directives={
            "language_level": "3",
            "boundscheck": False,
            "wraparound": False,
            "cdivision": True,
        },
        annotate=True,
    ),
)
