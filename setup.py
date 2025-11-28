"""
Build script for dot-ring.

Builds:
1. Cython extensions for performance-critical code
2. blst library bindings (BLS12-381 cryptography)

Requirements:
- C compiler (gcc/clang)
- SWIG (for blst bindings)
- Cython
"""

import os
import sys
import subprocess
import shutil
from pathlib import Path
from setuptools import setup, Extension, find_packages
from setuptools.command.build_ext import build_ext
from Cython.Build import cythonize


cython_extensions = [
    Extension(
        "dot_ring.curve.field_arithmetic",
        ["dot_ring/curve/field_arithmetic.pyx"],
        extra_compile_args=["-O3", "-ffast-math"],
    ),
    Extension(
        "dot_ring.curve.fast_math",
        ["dot_ring/curve/fast_math.pyx"],
        extra_compile_args=["-O3", "-ffast-math"],
    ),
    Extension(
        "dot_ring.ring_proof.polynomial.ntt",
        ["dot_ring/ring_proof/polynomial/ntt.pyx"],
        extra_compile_args=["-O3", "-ffast-math"],
    ),
]


class CustomBuildExt(build_ext):
    """Custom build that also compiles blst bindings."""

    def run(self):
        super().run()
        self.build_blst()

    def build_blst(self):
        """Build blst library bindings from source."""
        root_dir = Path(__file__).parent.absolute()
        dest_dir = root_dir / "dot_ring" / "blst"
        blst_dir = root_dir / ".blst"

        print("Building blst bindings...")

        # Clone blst if not present
        if not blst_dir.exists():
            print("Cloning blst repository...")
            subprocess.check_call([
                "git", "clone", "--depth", "1",
                "https://github.com/supranational/blst.git",
                str(blst_dir)
            ])

        # Clean previous build artifacts (may be for different platform)
        self._clean_blst_artifacts(blst_dir)

        # Build blst
        bindings_dir = blst_dir / "bindings" / "python"
        run_me = bindings_dir / "run.me"

        if not run_me.exists():
            raise RuntimeError("blst/bindings/python/run.me not found")

        os.chmod(run_me, 0o755)

        if sys.platform == "win32":
            subprocess.check_call(["sh", str(run_me)], cwd=bindings_dir)
        else:
            subprocess.check_call([str(run_me)], cwd=bindings_dir)

        # Copy artifacts to dot_ring/blst
        dest_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy(bindings_dir / "blst.py", dest_dir / "__init__.py")

        # Copy shared library
        copied = False
        for ext in ["*.so", "*.dylib", "*.dll"]:
            for f in bindings_dir.glob(ext):
                print(f"Copying {f.name} to {dest_dir}")
                shutil.copy(f, dest_dir / f.name)
                copied = True

        if not copied:
            raise RuntimeError("Failed to build blst shared library")

    def _clean_blst_artifacts(self, blst_dir: Path):
        """Clean previous blst build artifacts."""
        for pattern in ["libblst.a", "**/*.o", "**/*.so", "**/*.dylib"]:
            for f in blst_dir.glob(pattern):
                f.unlink()

        bindings_dir = blst_dir / "bindings" / "python"
        for f in ["blst.py", "blst_wrap.cpp"]:
            path = bindings_dir / f
            if path.exists():
                path.unlink()


setup(
    name="dot-ring",
    version="0.1.2",
    packages=find_packages(exclude=["tests*", "perf*"]),
    ext_modules=cythonize(
        cython_extensions,
        compiler_directives={
            "language_level": "3",
            "boundscheck": False,
            "wraparound": False,
            "cdivision": True,
        },
    ),
    cmdclass={"build_ext": CustomBuildExt},
    package_data={
        "dot_ring": ["py.typed"],
        "dot_ring.blst": ["*.so", "*.dylib", "*.dll", "*.pyd"],
        "dot_ring.vrf": ["data/*.bin"],
        "dot_ring.ring_proof": ["columns/*.json"],
    },
    include_package_data=True,
)
