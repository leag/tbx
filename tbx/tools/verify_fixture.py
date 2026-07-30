"""Byte-exact round-trip verification of corpus fixtures through the oracle.

    python -m tbx.tools.verify_fixture STEM [STEM ...]
    python -m tbx.tools.verify_fixture --all

For each corpus stem: decompile the EXE, emit source, compile that source
with the REAL Turbo Basic compiler (tbx.tools.oracle), and byte-compare the
result against the original EXE. This automates the calibration rule's
verification step for machines with the oracle available (TBX_ORACLE).

`v10_` stems compile with the TB 1.0 floppy. Fixtures with IDE Options
toggles (non-empty Program.toggles: the f* stems) are skipped -- the oracle
compiles with default Options, so their EXEs can never match.
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

from tbx import decode0, emit0
from tbx.tools import oracle

_CORPUS = Path(__file__).resolve().parent.parent.parent / "tests" / "fixtures" / "corpus"


def verify(stem: str) -> str:
    """'ok' | 'skip: ...' | 'MISMATCH: ...' for one corpus stem."""
    exe = (_CORPUS / f"{stem}.exe").read_bytes()
    prog = decode0.decode_user_code(exe)
    toggles = getattr(prog, "toggles", "")
    if toggles:
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
