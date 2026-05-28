from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

BLST_REPO_URL = os.environ.get("DOT_RING_BLST_REPO_URL", "https://github.com/Chainscore/blst.git")
BLST_REF = os.environ.get("DOT_RING_BLST_REF", "fix/python-as-memory-refcount")
BLST_COMMIT = os.environ.get("DOT_RING_BLST_COMMIT", "6a9bf56bed152ff136246cceae5c2553acab1e47")


def ensure_blst_source(root_dir: Path) -> Path:
    """Fetch the pinned blst fork revision used to build Python bindings."""
    blst_dir = root_dir / ".blst"

    if blst_dir.exists() and not (blst_dir / ".git").exists():
        shutil.rmtree(blst_dir)

    if not blst_dir.exists():
        blst_dir.mkdir(parents=True)
        subprocess.check_call(["git", "init"], cwd=blst_dir)
        subprocess.check_call(["git", "remote", "add", "origin", BLST_REPO_URL], cwd=blst_dir)
    else:
        subprocess.check_call(["git", "remote", "set-url", "origin", BLST_REPO_URL], cwd=blst_dir)

    subprocess.check_call(["git", "fetch", "--depth", "1", "origin", BLST_REF], cwd=blst_dir)
    subprocess.check_call(["git", "checkout", "--force", BLST_COMMIT], cwd=blst_dir)
    subprocess.check_call(["git", "clean", "-fdx"], cwd=blst_dir)

    print(f"Using blst {BLST_REPO_URL}@{BLST_COMMIT}")
    return blst_dir


def main() -> int:
    root_dir = Path(__file__).resolve().parent.parent
    ensure_blst_source(root_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
