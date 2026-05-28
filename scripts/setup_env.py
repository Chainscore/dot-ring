import subprocess
import sys
from pathlib import Path


def build_extensions() -> None:
    root_dir = Path(__file__).parent.parent
    subprocess.check_call([sys.executable, "setup.py", "build_ext", "--inplace"], cwd=root_dir)


if __name__ == "__main__":
    build_extensions()
