"""Small source repairs for the best-effort (tbd) output.

``dedupe_declarations`` drops names a SUB already declared LOCAL or SHARED
("Duplicate variable declaration"); ``insert_segments`` adds ``$SEGMENT``
breaks between top-level statements, since Turbo Basic limits each code
segment to 64 KiB and tbd does not track code size.
"""

from __future__ import annotations

import re

from tbdc.structure import _COST, _pairs, _statements

_DECL = re.compile(r"^(\s*(?:\d+\s+)?)(LOCAL|SHARED|STATIC)\s+(.*)$", re.IGNORECASE)
_SUB = re.compile(r"^\s*(?:\d+\s+)?(SUB\s|DEF\s+FN)", re.IGNORECASE)
_END = re.compile(r"^\s*(?:\d+\s+)?END\s+(SUB|DEF)\b", re.IGNORECASE)


def dedupe_declarations(source: str) -> tuple[str, int]:
    newline = "\r\n" if "\r\n" in source else "\n"
    lines = source.split(newline)
    seen: set[str] = set()
    removed = 0
    for i, line in enumerate(lines):
        if _SUB.match(line) or _END.match(line):
            seen = set()
            continue
        m = _DECL.match(line)
        if not m:
            continue
        names = [n.strip() for n in m.group(3).split(",") if n.strip()]
        keep = []
        for name in names:
            key = name.upper()
            if key in seen:
                removed += 1
                continue
            seen.add(key)
            keep.append(name)
        if len(keep) != len(names):
            lines[i] = f"{m.group(1)}{m.group(2)} {', '.join(keep)}" if keep else f"{m.group(1)}REM"
    return newline.join(lines), removed


def insert_segments(source: str, every: int = 500) -> tuple[str, int]:
    """Insert ``$SEGMENT`` about every ``every`` lines at top level."""

    newline = "\r\n" if "\r\n" in source else "\n"
    lines = source.split(newline)
    if len(lines) <= every:
        return source, 0
    stmts = _statements(lines)
    pairs, _ = _pairs(stmts)
    inside = [0] * (len(lines) + 1)
    for p in pairs:
        if p.kind not in _COST:
            continue
        a, b = stmts[p.open].line, stmts[p.close].line
        inside[a + 1] += 1
        inside[b + 1] -= 1
    depth, open_at = 0, []
    for i in range(len(lines)):
        depth += inside[i]
        open_at.append(depth)
    out: list[str] = []
    since = 0
    added = 0
    for i, line in enumerate(lines):
        since += 1
        if "$SEGMENT" in line.upper():
            since = 0
        elif since >= every and open_at[i] == 0 and line.strip() and not line.lstrip().startswith(("$", "CASE", "ELSE", "END", "LOOP", "NEXT", "WEND")) and not lines[i - 1].rstrip().endswith("_"):
            out.append("$SEGMENT")
            since = 0
            added += 1
        out.append(line)
    return newline.join(out), added
