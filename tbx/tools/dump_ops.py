"""Regenerate the canonical op-stream fixtures, one per corpus EXE.

Run from the repo root:
    python tbx/tools/dump_ops.py

Canonical form:
    # <stem> dialect=<name> start=<ADDR:05X>
    <ADDR:05X>:<kind>[:<arg>...]      (ops, in scan order)
    # commits
    <ADDR:05X>                        (commit markers, ascending)

Integer args print as signed decimal, char/name args literally; memory-form
FP ops carry a `far_` prefix iff far. Commit markers are collected on the
side by the scan rather than appearing as ops.
"""

import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tbx import decode0

CORPUS = ROOT / "tests" / "fixtures" / "corpus"
OUT = ROOT / "tests" / "fixtures" / "ops"


def canon_line(op: tuple[Any, ...]) -> str:
    addr, kind, *args = op
    parts = [f"{addr:05X}:{kind}"]
    for a in args:
        parts.append(str(a))
    return ":".join(parts)


def canon(stem: str, start: int, dia, ops: list[Any], commits: set[int]) -> str:
    lines = [f"# {stem} dialect={dia.name} start={start:05X}"]
    lines += [canon_line(o) for o in ops]
    lines.append("# commits")
    lines += [f"{c:05X}" for c in sorted(commits)]
    return "\n".join(lines) + "\n"


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    for exe_path in sorted(CORPUS.glob("*.exe")):
        exe = exe_path.read_bytes()
        start, dia = decode0.find_prologue(exe)
        commits = set()
        ops = decode0._scan(exe, start, dia, commits)
        text = canon(exe_path.stem, start, dia, ops, commits)
        (OUT / f"{exe_path.stem}.txt").write_text(text)
    print(f"wrote {sum(1 for _ in CORPUS.glob('*.exe'))} fixtures to {OUT}")


if __name__ == "__main__":
    main()
