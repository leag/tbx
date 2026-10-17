"""Show the source around a Turbo Basic compile error found by evaluate.py.

    uv run python scripts/errline.py build/eval1/NAME.exe [--context 15]

Turbo Basic leaves the failing line on the second-to-last row of the editor
window; this finds that row's text in the recovered source (or its includes).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tbdc.repair import error_row, locate  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("work", type=Path)
    ap.add_argument("--context", type=int, default=15)
    args = ap.parse_args()
    screen = (args.work / "error.txt").read_text()
    message, rows, cursor = error_row(screen)
    print(message, f"(cursor row {cursor})")
    sources = sorted(args.work.glob("*.BAS")) + sorted(args.work.glob("*.INC"))
    hit = locate(sources, rows, cursor)
    if hit is None:
        print(f"rows not found: {rows!r}")
        return 1
    path, index = hit
    lines = path.read_text(encoding="latin-1").splitlines()
    for i in range(max(0, index - args.context), min(len(lines), index + args.context // 2)):
        mark = ">>" if i == index else "  "
        print(f"{mark}{path.name}:{i + 1}: {lines[i]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
