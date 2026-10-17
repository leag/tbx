"""Reconcile CALL arguments with SUB signatures.

Turbo Basic passes variables by reference and rejects a variable whose type
differs from the parameter's ("Parameter mismatch"). When recovery types a
caller's variable and a callee's parameter differently, the call is
rewritten to pass that argument by value, ``(R)``, which the compiler
converts. Missing arguments get a zero or empty-string value and extra ones
are dropped. Every change is reported.
"""

from __future__ import annotations

import re

_NAME = r"[A-Za-z][A-Za-z0-9.]*"
_SUB = re.compile(rf"^\s*(?:\d+\s+)?SUB\s+({_NAME})\s*(?:\((.*)\))?\s*(INLINE)?\s*$", re.IGNORECASE)
_DEF = re.compile(r"^\s*(?:\d+\s+)?DEF(INT|LNG|SNG|DBL|STR)\s+(.*)$", re.IGNORECASE)
_LVALUE = re.compile(rf"^\s*({_NAME})([%&!#$]?)\s*(\(.*\))?\s*$")
_SUFFIX = {"INT": "%", "LNG": "&", "SNG": "!", "DBL": "#", "STR": "$"}
# Built-in functions look like array elements (`LEN(A$)`); they are values.
_BUILTINS = set(
    """ABS ASC ATN BIN CDBL CEIL CHR CINT CLNG COMMAND COS CSNG CSRLIN CVD CVI CVL
    CVMD CVMS CVS DATE EOF ENVIRON ERADR ERDEV ERL ERR EXP FIX FRE HEX INKEY INP
    INPUT INSTAT INSTR INT IOCTL LCASE LEFT LEN LOC LOF LOG LOG10 LOG2 LPOS MID
    MKD MKI MKL MKMD MKMS MKS OCT PEEK PEN PLAY PMAP POINT POS RIGHT RND SADD
    SCREEN SGN SIN SPACE SPC SQR STICK STR STRIG STRING TAB TAN TIME TIMER UCASE
    VAL VARPTR VARSEG""".split()
)


def _split_top(text: str, sep: str = ",") -> list[str]:
    parts, depth, quoted, start = [], 0, False, 0
    for i, ch in enumerate(text):
        if ch == '"':
            quoted = not quoted
        elif not quoted:
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
            elif ch == sep and depth == 0:
                parts.append(text[start:i])
                start = i + 1
    parts.append(text[start:])
    return parts


class _Types:
    def __init__(self, lines: list[str]):
        self.letters = {chr(c): "!" for c in range(ord("A"), ord("Z") + 1)}
        for line in lines:
            m = _DEF.match(line)
            if not m:
                continue
            suffix = _SUFFIX[m.group(1).upper()]
            for item in m.group(2).split(","):
                item = item.strip().upper()
                if re.fullmatch(r"[A-Z]\s*-\s*[A-Z]", item):
                    a, b = item[0], item[-1]
                    for c in range(ord(a), ord(b) + 1):
                        self.letters[chr(c)] = suffix
                elif re.fullmatch(r"[A-Z]", item):
                    self.letters[item] = suffix

    def of(self, name: str, suffix: str) -> str:
        return suffix or self.letters.get(name[:1].upper(), "!")


def reconcile_calls(source: str) -> tuple[str, list[str]]:
    newline = "\r\n" if "\r\n" in source else "\n"
    lines = source.split(newline)
    types = _Types(lines)
    subs: dict[str, list[tuple[str, bool]]] = {}
    for line in lines:
        m = _SUB.match(line)
        if not m or m.group(3):
            continue
        params = []
        for p in _split_top(m.group(2) or ""):
            p = p.strip()
            if not p:
                continue
            pm = re.match(rf"^({_NAME})([%&!#$]?)\s*(\(.*\))?$", p)
            if not pm:
                params = None
                break
            params.append((types.of(pm.group(1), pm.group(2)), pm.group(3) is not None))
        if params is not None:
            subs[m.group(1).upper()] = params
    notes: list[str] = []
    lines, subs = _adopt_argument_families(lines, subs, types, notes)
    lines = _adopt_parameter_types(lines, subs, types, notes)
    call = re.compile(rf"\bCALL\s+({_NAME})\s*\(", re.IGNORECASE)
    for index, line in enumerate(lines):
        if "CALL" not in line.upper():
            continue
        out, pos = [], 0
        for m in call.finditer(line):
            if m.start() < pos or _in_string(line, m.start()):
                continue
            name = m.group(1).upper()
            if name not in subs:
                continue
            open_at = m.end() - 1
            close_at = _matching(line, open_at)
            if close_at is None:
                continue
            args = _split_top(line[open_at + 1 : close_at])
            params = subs[name]
            new_args = []
            for i, arg in enumerate(args):
                if i >= len(params):
                    notes.append(f"dropped extra argument {arg.strip()!r} in CALL {name}")
                    continue
                kind, is_array = params[i]
                lv = _LVALUE.match(arg)
                if lv and lv.group(3) and lv.group(1).upper() in _BUILTINS:
                    lv = None
                if not is_array and lv and not lv.group(1).upper().startswith("FN"):
                    actual = types.of(lv.group(1), lv.group(2))
                    same_family = (actual == "$") == (kind == "$")
                    if actual != kind and same_family:
                        notes.append(f"passed {arg.strip()!r} by value to {kind} parameter of CALL {name}")
                        arg = f"({arg.strip()})"
                new_args.append(arg.strip())
            for kind, is_array in params[len(args):]:
                if is_array:
                    break
                new_args.append('""' if kind == "$" else "0")
                notes.append(f"supplied a missing argument in CALL {name}")
            out.append(line[pos:open_at] + "(" + ",".join(new_args) + ")")
            pos = close_at + 1
        if out:
            lines[index] = "".join(out) + line[pos:]
    return newline.join(lines), notes


def _in_string(line: str, at: int) -> bool:
    return line[:at].count('"') % 2 == 1


def _matching(line: str, open_at: int) -> int | None:
    depth, quoted = 0, False
    for i in range(open_at, len(line)):
        ch = line[i]
        if ch == '"':
            quoted = not quoted
        elif not quoted:
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    return i
    return None


def _calls(line: str, subs):
    """Yield (name, open, close, args) for each CALL of a known SUB on a line."""

    call = re.compile(rf"\bCALL\s+({_NAME})\s*\(", re.IGNORECASE)
    for m in call.finditer(line):
        if _in_string(line, m.start()):
            continue
        name = m.group(1).upper()
        if name not in subs:
            continue
        open_at = m.end() - 1
        close_at = _matching(line, open_at)
        if close_at is not None:
            yield name, open_at, close_at, _split_top(line[open_at + 1 : close_at])


def _scalar_uses(lines: list[str]) -> dict[str, int]:
    """How often each scalar variable spelling occurs outside strings."""

    counts: dict[str, int] = {}
    token = re.compile(rf"(?<![A-Za-z0-9.%&!#$]){_NAME}[%&!#$]?(?![A-Za-z0-9.(])")
    for line in lines:
        plain = re.sub(r'"[^"]*("|$)', '""', line)
        plain = re.sub(r"^\s*\d+", "", plain)
        for m in token.finditer(plain):
            word = m.group(0).upper()
            counts[word] = counts.get(word, 0) + 1
    return counts


def _adopt_parameter_types(lines, subs, types, notes):
    """Retype variables used only as CALL arguments to their parameter's type."""

    wanted: dict[str, set[str]] = {}
    passed: dict[str, int] = {}
    for line in lines:
        if "CALL" not in line.upper():
            continue
        for name, _, _, args in _calls(line, subs):
            for i, arg in enumerate(args):
                if i >= len(subs[name]):
                    break
                kind, is_array = subs[name][i]
                lv = _LVALUE.match(arg)
                if is_array or not lv or lv.group(3):
                    continue
                word = (lv.group(1) + lv.group(2)).upper()
                wanted.setdefault(word, set()).add(kind)
                passed[word] = passed.get(word, 0) + 1
    if not wanted:
        return lines
    uses = _scalar_uses(lines)
    renames: dict[str, str] = {}
    for word, kinds in wanted.items():
        name = re.match(_NAME, word).group(0)
        suffix = word[len(name):]
        actual = types.of(name, suffix)
        if len(kinds) != 1:
            continue
        (kind,) = kinds
        target = name + kind
        if actual == kind:
            continue
        if uses.get(word, 0) != passed[word] or target in uses:
            continue
        renames[word] = target
    if not renames:
        return lines
    for old, new in renames.items():
        notes.append(f"retyped {old} as {new}: it is only passed to {new[-1]} parameters")
    pattern = re.compile(
        rf"(?<![A-Za-z0-9.%&!#$])({'|'.join(re.escape(w) for w in sorted(renames, key=len, reverse=True))})(?![A-Za-z0-9.%&!#$(])",
        re.IGNORECASE,
    )

    def rename(line: str) -> str:
        parts = re.split(r'("[^"]*(?:"|$))', line)
        return "".join(
            part if part.startswith('"') else pattern.sub(lambda m: renames[m.group(1).upper()], part)
            for part in parts
        )

    return [rename(line) for line in lines]


_NUMERIC_FUNCS = {
    "ABS", "ASC", "ATN", "CDBL", "CEIL", "CINT", "CLNG", "COS", "CSNG", "CSRLIN", "CVD",
    "CVI", "CVL", "CVS", "EOF", "EXP", "FIX", "FRE", "INP", "INSTR", "INT", "LEN", "LOC",
    "LOF", "LOG", "PEEK", "POS", "RND", "SADD", "SGN", "SIN", "SQR", "TAN", "TIMER", "VAL",
    "VARPTR", "VARSEG",
}


def _family(arg: str, types) -> str | None:
    """'$' for a string expression, '#' for a numeric one, None if unknown."""

    text = arg.strip()
    if not text:
        return None
    if text.startswith('"'):
        return "$"
    if re.match(r"^[-+]?(\d|\.\d|&H|&O)", text, re.IGNORECASE):
        return "#"
    m = re.match(rf"^\(*\s*({_NAME})([%&!#$]?)", text)
    if not m:
        return None
    name, suffix = m.group(1).upper(), m.group(2)
    if name.startswith("FN"):
        return "$" if suffix == "$" else ("#" if suffix else None)
    if name in _NUMERIC_FUNCS and not suffix:
        return "#"
    return "$" if types.of(name, suffix) == "$" else "#"


def _adopt_argument_families(lines, subs, types, notes):
    """Retype a parameter that every caller fills with the other family.

    A parameter recovered as numeric that every CALL passes a string to (or
    the reverse) cannot be fixed at the call; its declaration is what is
    wrong (wild catalog.exe: `SUB SUB16(..., BO)` called with `STRING$(...)`).
    """

    seen: dict[str, list[set]] = {}
    for line in lines:
        if "CALL" not in line.upper():
            continue
        for name, _, _, args in _calls(line, subs):
            slots = seen.setdefault(name, [set() for _ in subs[name]])
            for i, arg in enumerate(args[: len(slots)]):
                slots[i].add(_family(arg, types))
    changed = False
    for name, slots in seen.items():
        params = subs[name]
        for i, families in enumerate(slots):
            kind, is_array = params[i]
            if is_array or len(families) != 1 or None in families:
                continue
            (family,) = families
            if (family == "$") == (kind == "$"):
                continue
            new_suffix = "$" if family == "$" else "!"
            lines, renamed = _retype_parameter(lines, name, i, new_suffix)
            if renamed:
                notes.append(f"retyped parameter {renamed} of SUB {name}: every call passes a {'string' if family == '$' else 'number'}")
                changed = True
    if changed:
        subs = _parse_subs(lines, types)
    return lines, subs


def _parse_subs(lines, types):
    subs: dict[str, list[tuple[str, bool]]] = {}
    for line in lines:
        m = _SUB.match(line)
        if not m or m.group(3):
            continue
        params = []
        for p in _split_top(m.group(2) or ""):
            p = p.strip()
            if not p:
                continue
            pm = re.match(rf"^({_NAME})([%&!#$]?)\s*(\(.*\))?$", p)
            if not pm:
                params = None
                break
            params.append((types.of(pm.group(1), pm.group(2)), pm.group(3) is not None))
        if params is not None:
            subs[m.group(1).upper()] = params
    return subs


def _retype_parameter(lines, sub, index, suffix):
    start = next(
        (i for i, line in enumerate(lines) if (m := _SUB.match(line)) and m.group(1).upper() == sub),
        None,
    )
    if start is None:
        return lines, None
    m = _SUB.match(lines[start])
    params = [p.strip() for p in _split_top(m.group(2) or "")]
    pm = re.match(rf"^({_NAME})([%&!#$]?)$", params[index])
    if not pm:
        return lines, None
    old, new = pm.group(1) + pm.group(2), pm.group(1) + suffix
    end = next(
        (i for i in range(start + 1, len(lines)) if re.match(r"^\s*(?:\d+\s+)?END\s+SUB\b", lines[i], re.IGNORECASE)),
        len(lines) - 1,
    )
    body = lines[start : end + 1]
    if any(re.search(rf"(?<![A-Za-z0-9.%&!#$]){re.escape(new)}(?![A-Za-z0-9.(])", re.sub(r'"[^"]*"', '""', b), re.IGNORECASE) for b in body):
        return lines, None  # the new spelling is taken
    pattern = re.compile(rf"(?<![A-Za-z0-9.%&!#$]){re.escape(old)}(?![A-Za-z0-9.%&!#$(])", re.IGNORECASE)

    def rename(line: str) -> str:
        parts = re.split(r'("[^"]*(?:"|$))', line)
        return "".join(p if p.startswith('"') else pattern.sub(new, p) for p in parts)

    return lines[:start] + [rename(b) for b in body] + lines[end + 1 :], f"{old} as {new}"
