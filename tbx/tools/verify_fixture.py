"""Byte-exact round-trip verification of corpus fixtures through the oracle.

    python -m tbx.tools.verify_fixture STEM [STEM ...]
    python -m tbx.tools.verify_fixture --all

For each corpus stem: decompile the EXE, emit source, compile that source
with the REAL Turbo Basic compiler (tbx.tools.oracle), and byte-compare the
result against the original EXE. This automates the calibration rule's
verification step for machines with the oracle available (TBX_ORACLE).

`v10_` stems compile with the TB 1.0 floppy. Fixtures with IDE Options toggles
(the f* stems) are skipped when the toggle EMITS CODE the oracle cannot be
asked for -- Bounds is +128 bytes, Stack test +3, 8087 a different runtime.
Keyboard break is not one of those: it leaves only the flags mask, one byte, so
`fkb_` stems are verified with that byte normalized instead of skipped. The
blanket "a toggled EXE can never match" this file used to state was wrong for
K, and skipping on it is how two wild emitter bugs stayed hidden (see
`verify_wild.FLAGS_ONLY_TOGGLES`).
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

from tbx import decode0, emit0
from tbx.tools import oracle
from tbx.tools.verify_wild import FLAGS_ONLY_TOGGLES, normalize_flags

_CORPUS = Path(__file__).resolve().parent.parent.parent / "tests" / "fixtures" / "corpus"


def verify(stem: str) -> str:
    """'ok' | 'skip: ...' | 'MISMATCH: ...' for one corpus stem."""
    exe = (_CORPUS / f"{stem}.exe").read_bytes()
    prog = decode0.decode_user_code(exe)
    toggles = getattr(prog, "toggles", "")
    if set(toggles) - FLAGS_ONLY_TOGGLES:
        return f"skip: Options toggles {decode0.toggle_names(toggles)}"
    src = emit0.emit(prog)
    dialect = "1.0" if stem.startswith("v10_") else "1.1"
    with tempfile.NamedTemporaryFile(
        "w", suffix=".bas", encoding="latin-1", delete=False
    ) as f:
        f.write(src)
        bas = f.name
    try:
        out = oracle.compile_bas(bas, dialect=dialect)
    finally:
        Path(bas).unlink(missing_ok=True)
    if out == exe:
        return "ok"
    if toggles:  # flags-only: the mask itself is the one byte we cannot ask for
        start = decode0.find_prologue(exe)[0]
        if normalize_flags(out, start) == normalize_flags(exe, start):
            return f"ok bar the Options flags byte ({decode0.toggle_names(toggles)})"
    n = sum(a != b for a, b in zip(out, exe)) + abs(len(out) - len(exe))
    return f"MISMATCH: {len(out)} B vs {len(exe)} B, ~{n} bytes differ"


def main(argv: list[str]) -> int:
    if argv and argv[0] == "--all":
        stems = sorted(p.stem for p in _CORPUS.glob("*.exe"))
    else:
        stems = argv
    if not stems:
        print(__doc__)
        return 2
    bad = 0
    for stem in stems:
        r = verify(stem)
        print(f"{stem}: {r}")
        if r.startswith("MISMATCH"):
            bad += 1
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
