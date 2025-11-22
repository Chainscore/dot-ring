from distutils.core import setup
from mypyc.build import mypycify
import os

# List of files to compile
files = [
    'dot_ring/curve/curve.py',
]

# Ensure files exist
for f in files:
    if not os.path.exists(f):
        print(f"File not found: {f}")
        exit(1)

setup(
    name='dot_ring_compiled',
    packages=['dot_ring'],
    ext_modules=mypycify(files),
)
