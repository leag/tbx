"""Regenerate the golden BASIC fixtures: emit(decode_user_code(exe)) for each
corpus EXE. Companion to dump_ops.py.

Compiler-flag fixtures (non-empty Program.toggles) get NO golden by
convention: their emitted source is identical to the unflagged program's
(tests/tbx/test_flags.py pins that directly), and a golden would pull them
into the usercode/IR-snapshot sweeps as duplicates.

Run from the repo root:
    python tbx/tools/dump_user_code.py
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tbx import decode0, emit0

CORPUS = ROOT / "tests" / "fixtures" / "corpus"
OUT = ROOT / "tests" / "fixtures" / "usercode"


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    n = skipped = 0
    for exe_path in sorted(CORPUS.glob("*.exe")):
        stmts = decode0.decode_user_code(exe_path.read_bytes())
        if getattr(stmts, "toggles", ""):
            skipped += 1
            continue
        (OUT / f"{exe_path.stem}.bas").write_text(emit0.emit(stmts))
        n += 1
    print(f"wrote {n} fixtures to {OUT} ({skipped} flag fixtures skipped)")


if __name__ == "__main__":
    main()
