"""Locate Turbo Basic compile errors in recovered source.

After a compile error the IDE opens the editor on the failing line, puts the
error message over the window's first row and leaves the text cursor on the
offending token. The harness reports that cursor (``Cursor: row,col``); the
window's rows identify which file and line it is on.
"""

from __future__ import annotations

import re
from pathlib import Path

WIDTH = 68  # text columns the editor window shows (the 69th stays blank)
FIRST_ROW = 5  # screen row of the first source row under the error message


def _window(screen: str) -> list[str]:
    rows: list[str] = []
    inside = False
    for line in screen.splitlines():
        if "═ Edit ═" in line:
            inside = True
            continue
        if inside:
            if line.startswith("╚"):
                break
            if line.startswith("║"):
                rows.append(line[1:].split("║", 1)[0])
    return rows


def error_row(screen: str) -> tuple[str, list[str], int | None]:
    """Return the error message, the visible source rows and the cursor's row index."""

    rows = _window(screen)
    cursor = re.search(r"Cursor:\s*(\d+),(\d+)", screen)
    index = None
    if cursor:
        index = int(cursor.group(1)) - FIRST_ROW
    if not rows:
        return "", [], index
    return rows[0].strip(), rows[1:], index


def _fits(line: str, row: str, shift: int) -> bool:
    text = line.expandtabs(8)[shift : shift + WIDTH].rstrip()
    return text == row[:WIDTH].rstrip()


def locate(sources: list[Path], rows: list[str], cursor: int | None = None) -> tuple[Path, int] | None:
    """Find the failing line: ``(file, zero-based line index)``."""

    if not rows:
        return None
    n = len(rows)
    target = cursor if cursor is not None and 0 <= cursor < n else n - 2
    for path in sources:
        lines = path.read_text(encoding="latin-1").splitlines()
        shifts = [0]
        anchor = rows[target].strip()
        if anchor:
            # A long line scrolls the window sideways; find the shift from it.
            for line in lines:
                at = line.find(anchor)
                if at > 0:
                    shifts.extend(s for s in range(max(0, at - WIDTH), at + 1) if s not in shifts)
                    break
        for shift in shifts:
            for start in range(0, max(1, len(lines) - n + 2)):
                window = lines[start : start + n]
                if len(window) < min(n, target + 1):
                    break
                if all(_fits(a, b, shift) for a, b in zip(window, rows)):
                    return path, min(start + target, len(lines) - 1)
    return None
