import os
import sys
import subprocess
import shutil
from pathlib import Path
from setuptools import setup, Extension, find_packages
from setuptools.command.build_ext import build_ext
from Cython.Build import cythonize

# Define Cython extensions
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
    def run(self):
        # 1. Build Cython extensions
        super().run()
        
        # 2. Build blst bindings
        self.build_blst()

    def build_blst(self):
        print("Building blst bindings...")
        root_dir = Path(__file__).parent.absolute()
        blst_dir = root_dir / ".blst"
        
        # Check if blst source exists
        if not blst_dir.exists():
            print("Cloning blst...")
            subprocess.check_call(["git", "clone", "https://github.com/supranational/blst.git", str(blst_dir)])
        
        bindings_dir = blst_dir / "bindings" / "python"
        run_me = bindings_dir / "run.me"
        
        if not run_me.exists():
             print("Error: run.me not found in blst bindings. Re-cloning...")
             shutil.rmtree(blst_dir)
             subprocess.check_call(["git", "clone", "https://github.com/supranational/blst.git", str(blst_dir)])
        
        # Ensure run.me is executable
        os.chmod(run_me, 0o755)
        
        # Run the build script
        if sys.platform == "win32":
            # On Windows, try to use git bash's sh.exe or similar if available
            # Or just assume sh is in path (e.g. from Git)
            subprocess.check_call(["sh", str(run_me)], cwd=bindings_dir)
        else:
            subprocess.check_call([str(run_me)], cwd=bindings_dir)
        
        # Copy artifacts to dot_ring/blst
        dest_dir = root_dir / "dot_ring" / "blst"
        dest_dir.mkdir(parents=True, exist_ok=True)
        
        # Copy blst.py -> __init__.py
        shutil.copy(bindings_dir / "blst.py", dest_dir / "__init__.py")
        
        # Copy shared library
        extensions = ["*.so", "*.dylib", "*.dll"]
        copied = False
        for ext in extensions:
            for file in bindings_dir.glob(ext):
                print(f"Copying {file.name} to {dest_dir}...")
                shutil.copy(file, dest_dir / file.name)
                copied = True
        
        if not copied:
            raise RuntimeError("Failed to build/find blst shared library")

setup(
    name="dot-ring",
    version="0.1.0",
    packages=find_packages(),
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
        "dot_ring.blst": ["*.so", "*.dylib", "*.dll"],
    },
    include_package_data=True,
)
