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
import shutil
import subprocess
import sys
from pathlib import Path

from Cython.Build import cythonize
from setuptools import Extension, find_packages, setup
from setuptools.command.build_ext import build_ext


def get_compile_args() -> list[str]:
    args = ["-O3", "-ffast-math", "-flto"]
    if sys.platform != "darwin":
        args.append("-march=native")
    return args


def build_cython_extensions() -> list[Extension]:
    compile_args = get_compile_args()
    return [
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
        Extension(
            "dot_ring.curve.native_field.scalar",
            [
                "dot_ring/curve/native_field/scalar.pyx",
                "dot_ring/curve/native_field/bls12_381_scalar.c",
            ],
            include_dirs=["dot_ring/curve/native_field"],
            extra_compile_args=compile_args,
            extra_link_args=["-flto"],
        ),
        Extension(
            "dot_ring.curve.native_field.vector_ops",
            [
                "dot_ring/curve/native_field/vector_ops.pyx",
                "dot_ring/curve/native_field/bls12_381_scalar.c",
            ],
            include_dirs=["dot_ring/curve/native_field"],
            extra_compile_args=compile_args,
            extra_link_args=["-flto"],
        ),
    ]


cython_extensions = build_cython_extensions()


class CustomBuildExt(build_ext):
    """Custom build that also compiles blst bindings."""

    def run(self) -> None:
        # Build blst FIRST so it's available for packaging
        self.build_blst()
        super().run()
        self.copy_blst_to_build()

    def copy_blst_to_build(self) -> None:
        """Copy blst artifacts to the build output directory."""
        root_dir = Path(__file__).parent.absolute()
        src_blst = root_dir / "dot_ring" / "blst"

        if not src_blst.exists():
            return

        # Get the build lib directory
        build_lib = Path(self.build_lib) / "dot_ring" / "blst"
        build_lib.mkdir(parents=True, exist_ok=True)

        # Copy all blst files to build directory
        for f in src_blst.iterdir():
            if f.is_file():
                shutil.copy(f, build_lib / f.name)
                print(f"Copied {f.name} to build directory")

    def build_blst(self) -> None:
        """Build blst library bindings from source."""
        root_dir = Path(__file__).parent.absolute()
        dest_dir = root_dir / "dot_ring" / "blst"
        blst_dir = root_dir / ".blst"

        print("Building blst bindings...")

        # Clone blst if not present
        if not blst_dir.exists():
            print("Cloning blst repository...")
            subprocess.check_call(
                [
                    "git",
                    "clone",
                    "--depth",
                    "1",
                    "https://github.com/supranational/blst.git",
                    str(blst_dir),
                ]
            )

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

    def _clean_blst_artifacts(self, blst_dir: Path) -> None:
        """Clean previous blst build artifacts."""
        for pattern in ["libblst.a", "**/*.o", "**/*.so", "**/*.dylib"]:
            for f in blst_dir.glob(pattern):
                f.unlink()

        bindings_dir = blst_dir / "bindings" / "python"
        for filename in ["blst.py", "blst_wrap.cpp"]:
            path = bindings_dir / filename
            if path.exists():
                path.unlink()


setup(
    name="dot-ring",
    version="0.1.2",
    packages=find_packages(exclude=["tests*", "perf*"]) + ["dot_ring.blst"],
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
