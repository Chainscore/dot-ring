from __future__ import annotations

import sys
from pathlib import Path

PATCH_MARKER = "Py_DECREF(obj$argnum);  // release backing bytes held by memoryview"

ARGOUT_TYPEMAP = """%typemap(argout) POINT points[] %{
    $result = PyMemoryView_FromObject(obj$argnum);
    if ($result != NULL) {
        // .itemsize to return size of point, and len() - amount of points
        PyMemoryView_GET_BUFFER($result)->itemsize  = sizeof($1[0]);
        PyMemoryView_GET_BUFFER($result)->shape[0] /= sizeof($1[0]);
    } else {
        Py_DECREF(obj$argnum);
    }
%}"""

PATCHED_ARGOUT_TYPEMAP = """%typemap(argout) POINT points[] %{
    $result = PyMemoryView_FromObject(obj$argnum);
    if ($result != NULL) {
        // .itemsize to return size of point, and len() - amount of points
        PyMemoryView_GET_BUFFER($result)->itemsize  = sizeof($1[0]);
        PyMemoryView_GET_BUFFER($result)->shape[0] /= sizeof($1[0]);
        Py_DECREF(obj$argnum);  // release backing bytes held by memoryview
    } else {
        Py_DECREF(obj$argnum);
    }
%}"""


def patch_blst_swg(blst_dir: Path) -> None:
    swg_path = blst_dir / "bindings" / "blst.swg"
    if not swg_path.exists():
        raise FileNotFoundError(f"Could not find blst SWIG file: {swg_path}")

    text = swg_path.read_text()
    if PATCH_MARKER in text:
        print(f"blst SWIG memoryview patch already applied: {swg_path}")
        return

    if ARGOUT_TYPEMAP not in text:
        raise RuntimeError(f"Could not find expected POINT points[] argout typemap in {swg_path}")

    swg_path.write_text(text.replace(ARGOUT_TYPEMAP, PATCHED_ARGOUT_TYPEMAP, 1))
    print(f"Applied blst SWIG memoryview patch: {swg_path}")


def main() -> int:
    root_dir = Path(__file__).resolve().parent.parent
    blst_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else root_dir / ".blst"
    patch_blst_swg(blst_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
