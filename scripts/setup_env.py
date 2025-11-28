import os
import subprocess
import sys
import shutil
from pathlib import Path
import site

def install_blst():
    root_dir = Path(__file__).parent.parent
    blst_dir = root_dir / ".blst"
    
    # 1. Clone blst if not exists or is invalid
    should_clone = False
    if not blst_dir.exists():
        should_clone = True
    else:
        # Check if it looks like a valid clone (has bindings/python/run.me)
        if not (blst_dir / "bindings" / "python" / "run.me").exists():
            print("Existing blst directory seems incomplete. Re-cloning...")
            shutil.rmtree(blst_dir)
            should_clone = True
        else:
            print("blst already cloned.")

    if should_clone:
        print("Cloning blst...")
        subprocess.check_call(["git", "clone", "https://github.com/supranational/blst.git", str(blst_dir)])

    # 2. Build python bindings
    print("Building blst python bindings...")
    bindings_dir = blst_dir / "bindings" / "python"
    
    # Ensure run.me is executable
    run_me = bindings_dir / "run.me"
    if run_me.exists():
        os.chmod(run_me, 0o755)
        subprocess.check_call(["./run.me"], cwd=bindings_dir)
    else:
        print("Error: run.me not found in blst bindings.")
        sys.exit(1)

    # 3. Install into current python environment
    # We try to find the site-packages directory of the current environment
    site_packages = None
    
    # Check if we are in a virtual environment
    if sys.prefix != sys.base_prefix:
        # We are in a venv
        if os.name == 'posix':
            site_packages = Path(sys.prefix) / "lib" / f"python{sys.version_info.major}.{sys.version_info.minor}" / "site-packages"
        elif os.name == 'nt':
            site_packages = Path(sys.prefix) / "Lib" / "site-packages"
    
    # Fallback if not found or not in venv (though we recommend venv)
    if not site_packages or not site_packages.exists():
        # Try to find a user site-packages or system one that is writable
        # This is a bit heuristic.
        paths = site.getsitepackages()
        if paths:
            site_packages = Path(paths[0])
        else:
            usersite = site.getusersitepackages()
            if usersite:
                site_packages = Path(usersite)

    if not site_packages or not site_packages.exists():
        print("Error: Could not determine site-packages directory.")
        sys.exit(1)

    print(f"Installing blst to {site_packages}...")
    
    # Copy blst.py
    if (bindings_dir / "blst.py").exists():
        shutil.copy(bindings_dir / "blst.py", site_packages / "blst.py")
    else:
        print("Error: blst.py not found.")
        sys.exit(1)
    
    # Copy shared library
    # Extensions can be .so, .dylib, .dll
    extensions = ["*.so", "*.dylib", "*.dll"]
    copied = False
    for ext in extensions:
        for file in bindings_dir.glob(ext):
            print(f"Copying {file.name}...")
            shutil.copy(file, site_packages / file.name)
            copied = True
    
    if not copied:
        print("Warning: No shared library (.so, .dylib, .dll) found to copy.")
    else:
        print("blst installed successfully.")

def build_cython_extensions():
    print("Building Cython extensions...")
    root_dir = Path(__file__).parent.parent
    # Prefer script in scripts/ if present, fallback to repository root
    setup_script = root_dir / "scripts" / "setup_cython.py"
    if not setup_script.exists():
        setup_script = root_dir / "setup_cython.py"
    
    if not setup_script.exists():
        print("Error: setup_cython.py not found in scripts/ or root.")
        sys.exit(1)

    subprocess.check_call([sys.executable, str(setup_script), "build_ext", "--inplace"], cwd=root_dir)
    print("Cython extensions built successfully.")

if __name__ == "__main__":
    install_blst()
    build_cython_extensions()
