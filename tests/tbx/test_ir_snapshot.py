"""IR-snapshot regression: a finer gate than the emitted-source goldens.

The usercode goldens gate the *final* emitted text. This snapshot freezes the
*typed IR* that `decode0.decode_user_code` returns -- one `repr()` per
statement -- for every corpus EXE that has a usercode golden. Any drift in
the decoder therefore fails here *before* it is flattened through emit,
pinpointing the exact program and statement index that changed.

Regenerate after an *intended* IR change:
    uv run python tests/tbx/test_ir_snapshot.py --write
"""

import glob
import os

from tbx import decode0

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_CORPUS = os.path.join(_ROOT, "fixtures", "corpus")
_GOLD = os.path.join(_ROOT, "fixtures", "usercode")
_SNAPSHOT = os.path.join(_ROOT, "fixtures", "ir_snapshot.txt")


def _sweep():
    """(stem, exe_path) for every corpus EXE that has a usercode golden."""
    pairs = []
    for exe in sorted(glob.glob(os.path.join(_CORPUS, "*.exe"))):
        stem = os.path.splitext(os.path.basename(exe))[0]
        if os.path.exists(os.path.join(_GOLD, f"{stem}.bas")):
            pairs.append((stem, exe))
    return pairs


def _build() -> str:
    """The canonical snapshot text: a `## <stem>` header per program, then one
    statement repr per line, blocks separated by a blank line."""
    blocks = []
    for stem, path in _sweep():
        prog = decode0.decode_user_code(open(path, "rb").read())
        body = "\n".join(repr(s) for s in prog)
        blocks.append(f"## {stem}\n{body}")
    return "\n\n".join(blocks) + "\n"


def test_ir_snapshot():
    got = _build()
    want = open(_SNAPSHOT).read()
    if got == want:
        return
    # Localize the first differing line for a readable failure.
    gl, wl = got.splitlines(), want.splitlines()
    stem = "?"
    for i in range(max(len(gl), len(wl))):
        g = gl[i] if i < len(gl) else "<EOF>"
        w = wl[i] if i < len(wl) else "<EOF>"
        if g.startswith("## "):
            stem = g[3:]
        if g != w:
            raise AssertionError(
                f"IR snapshot drift in [{stem}] at line {i + 1}:\n"
                f"  got:  {g}\n  want: {w}\n"
                "If this change is intended, regenerate:\n"
                "  uv run python tests/tbx/test_ir_snapshot.py --write"
            )
    raise AssertionError("IR snapshot length mismatch")


if __name__ == "__main__":
    import sys

    if "--write" in sys.argv:
        open(_SNAPSHOT, "w").write(_build())
        print(f"wrote {_SNAPSHOT}")
    else:
        print("pass --write to regenerate the snapshot fixture")
