"""Make recovered source block-structured the way Turbo Basic requires.

A decoder that folds jumps into blocks can produce blocks that cross: a LOOP
inside a block IF that began after the DO, a NEXT inside a CASE arm, a DO
whose LOOP falls after the END IF that encloses the DO. Turbo Basic rejects
these ("END IF expected", "NEXT expected", ...), though the control flow they
describe is well defined.

``restructure`` pairs every opener with its closer, per construct, and where
two pairs overlap it rewrites one of them as labelled GOTOs, which have the
same meaning and no nesting rules. Block IFs are rewritten first, then
DO/WHILE loops, then SELECT CASE; FOR/NEXT, SUB and DEF FN are kept. Openers
or closers that have no partner become ``REM TBDC:`` comments.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

_NUMBER = re.compile(r"^(\s*)(\d+)(\s+|$)")
_JOIN = "\x01"  # marks a `_` line continuation inside a logical line
_LABEL = re.compile(r"^\s*[A-Za-z][A-Za-z0-9.]*:\s*$")
_WORD = re.compile(r"[A-Za-z][A-Za-z0-9.]*[%&!#$]?")


@dataclass
class Stmt:
    """One statement of a physical line."""

    line: int  # index into the line list
    start: int  # column where the statement text starts
    end: int  # column after the statement text
    kind: str  # opener/closer kind or "" for an ordinary statement
    text: str
    sole: bool  # the only statement on its line (besides a line number)


@dataclass
class Pair:
    kind: str  # "IF", "DO", "WHILE", "SELECT", "FOR", "SUB", "DEF"
    open: int  # index into the statement list
    close: int
    middles: list[int] = field(default_factory=list)  # ELSEIF/ELSE, CASE
    exits: list[int] = field(default_factory=list)  # EXIT LOOP for DO/WHILE


def _split_statements(text: str) -> list[tuple[int, int]]:
    """Spans of ``:``-separated statements, ignoring strings and comments."""

    spans: list[tuple[int, int]] = []
    start = 0
    i = 0
    quoted = False
    while i < len(text):
        ch = text[i]
        if ch == '"':
            quoted = not quoted
        elif not quoted:
            if ch == "'":
                break
            if ch == ":":
                spans.append((start, i))
                start = i + 1
            elif text[i : i + 3].upper() == "REM" and (i == start or text[start:i].strip() == "") and (
                i + 3 == len(text) or not text[i + 3].isalnum()
            ):
                break
        i += 1
    spans.append((start, len(text)))
    return spans


def _continues(line: str) -> bool:
    """Does the line end with a `_` continuation (outside strings/comments)?"""

    code = _strip_strings(line.split(_JOIN)[-1])
    if "'" in code:
        code = code[: code.index("'")]
    code = code.rstrip()
    return code.endswith("_") and (len(code) == 1 or not code[-2].isalnum())


def _words(text: str) -> list[str]:
    out: list[str] = []
    quoted = False
    i = 0
    while i < len(text):
        ch = text[i]
        if ch == '"':
            quoted = not quoted
            i += 1
            continue
        if not quoted:
            m = _WORD.match(text, i)
            if m and (i == 0 or not (text[i - 1].isalnum() or text[i - 1] in "%&!#$.")):
                out.append(m.group(0).upper())
                i = m.end()
                continue
        i += 1
    return out


def _classify(text: str) -> str:
    words = _words(text)
    if not words:
        return ""
    head = words[0]
    second = words[1] if len(words) > 1 else ""
    if head == "FOR":
        return "FOR"
    if head == "NEXT":
        return "NEXT"
    if head == "DO":
        return "DO"
    if head == "LOOP":
        return "LOOP"
    if head == "WHILE":
        return "WHILE"
    if head == "WEND":
        return "WEND"
    if head == "SELECT":
        return "SELECT"
    if head == "CASE":
        return "CASE"
    if head == "ELSEIF":
        return "ELSEIF"
    if head == "ELSE":
        return "ELSE"
    if head == "END" and second in ("IF", "SELECT", "SUB", "DEF"):
        return "END " + second
    if head == "EXIT" and second == "LOOP":
        return "EXIT LOOP"
    if head == "SUB" or (head == "DEF" and second.startswith("FN")):
        if head == "DEF" and "=" in _strip_strings(text):
            return ""
        return head
    if head == "IF" and re.search(r"\bTHEN\s*$", _strip_strings(text), re.IGNORECASE):
        return "IF"
    return ""


def _strip_strings(text: str) -> str:
    """Blank string literal contents, keeping every column where it was."""

    def blank(m: re.Match) -> str:
        body = m.group(0)
        closed = len(body) > 1 and body.endswith('"')
        return '"' + "_" * (len(body) - (2 if closed else 1)) + ('"' if closed else "")

    return re.sub(r'"[^"]*("|$)', blank, text)


def _inline_if(text: str) -> tuple[int, list[tuple[int, int]]] | None:
    """For a one-line IF, the spans of the statements after THEN/ELSE."""

    plain = _strip_strings(text)
    m = re.match(r"\s*IF\b.*?\bTHEN\b", plain, re.IGNORECASE)
    if not m:
        return None
    rest = text[m.end() :]
    if not rest.strip():
        return None
    spans = []
    for a, b in _split_statements(rest):
        piece = rest[a:b]
        # ELSE inside a one-line IF separates a second statement list.
        em = re.search(r"\bELSE\b", _strip_strings(piece), re.IGNORECASE)
        if em:
            spans.append((m.end() + a, m.end() + a + em.start()))
            spans.append((m.end() + a + em.end(), m.end() + b))
        else:
            spans.append((m.end() + a, m.end() + b))
    return m.end(), spans


_LOOP_KINDS = ("FOR", "DO", "WHILE", "NEXT", "LOOP", "WEND", "EXIT LOOP")


def _inline_loops(text: str, depth: int = 0):
    """Loop openers/closers inside a one-line IF, at any nesting depth."""

    inner = _inline_if(text)
    if not inner or depth > 8:
        return
    for ia, ib in inner[1]:
        sub = text[ia:ib]
        kind = _classify(sub)
        if kind in _LOOP_KINDS:
            yield ia, ib, kind
        elif kind == "" and _words(sub)[:1] == ["IF"]:
            for ja, jb, jk in _inline_loops(sub, depth + 1):
                yield ia + ja, ia + jb, jk


def _statements(lines: list[str]) -> list[Stmt]:
    stmts: list[Stmt] = []
    for index, line in enumerate(lines):
        body_start = 0
        m = _NUMBER.match(line)
        if m:
            body_start = m.end()
        if _LABEL.match(line) or line.strip().startswith("$"):
            continue
        spans = [(a + body_start, b + body_start) for a, b in _split_statements(line[body_start:])]
        spans = [(a, b) for a, b in spans if line[a:b].strip()]
        sole = len(spans) == 1
        for a, b in spans:
            text = line[a:b]
            kind = _classify(text)
            stmts.append(Stmt(index, a, b, kind, text, sole))
            if kind == "" and _words(text)[:1] == ["IF"]:
                for ia, ib, sk in _inline_loops(text):
                    stmts.append(Stmt(index, a + ia, a + ib, sk, text[ia:ib], False))
    return stmts


_CLOSE = {"NEXT": "FOR", "LOOP": "DO", "WEND": "WHILE", "END IF": "IF",
          "END SELECT": "SELECT", "END SUB": "SUB", "END DEF": "DEF"}
_COST = {"IF": 1, "DO": 2, "WHILE": 2, "SELECT": 3, "FOR": 100, "SUB": 1000, "DEF": 1000}


def _next_count(text: str) -> int:
    words = _words(text)
    return max(1, len(words) - 1)


def _pairs(stmts: list[Stmt]) -> tuple[list[Pair], list[int]]:
    """Pair openers and closers per construct; return pairs and orphans."""

    stacks: dict[str, list[int]] = {k: [] for k in _COST}
    pairs: dict[int, Pair] = {}
    orphans: list[int] = []
    loop_stack: list[int] = []  # DO/WHILE openers for EXIT LOOP, textual order
    for i, s in enumerate(stmts):
        k = s.kind
        if k in _COST:
            stacks[k].append(i)
            pairs[i] = Pair(k, i, -1)
            if k in ("DO", "WHILE"):
                loop_stack.append(i)
        elif k in _CLOSE:
            opener = _CLOSE[k]
            count = _next_count(s.text) if k == "NEXT" else 1
            for _ in range(count):
                if stacks[opener]:
                    o = stacks[opener].pop()
                    pairs[o].close = i
                    if o in loop_stack:
                        loop_stack.remove(o)
                else:
                    orphans.append(i)
                    break
        elif k in ("ELSEIF", "ELSE") and s.sole:
            if stacks["IF"]:
                pairs[stacks["IF"][-1]].middles.append(i)
            else:
                orphans.append(i)
        elif k == "CASE":
            if stacks["SELECT"]:
                pairs[stacks["SELECT"][-1]].middles.append(i)
            else:
                orphans.append(i)
        elif k == "EXIT LOOP":
            if loop_stack:
                pairs[loop_stack[-1]].exits.append(i)
    for k, stack in stacks.items():
        orphans.extend(stack)
        for o in stack:
            pairs.pop(o, None)
    return [p for p in pairs.values() if p.close >= 0], sorted(set(orphans))


def _overlap(a: Pair, b: Pair) -> bool:
    return a.open < b.open < a.close < b.close or b.open < a.open < b.close < a.close


def _crosses(a: Pair, b: Pair) -> bool:
    """True when the two pairs cannot both stay blocks."""

    if _overlap(a, b):
        return True
    for outer, inner in ((a, b), (b, a)):
        if outer.open < inner.open and inner.close < outer.close and outer.middles:
            def segment(x: int) -> int:
                return sum(1 for m in outer.middles if m < x)

            if segment(inner.open) != segment(inner.close):
                return True
    return False


@dataclass
class Restructured:
    source: str
    flattened: dict[str, int]
    orphans: list[str]


def restructure(source: str) -> Restructured:
    """Rewrite crossing blocks of ``source`` as GOTOs; see the module docstring."""

    newline = "\r\n" if "\r\n" in source else "\n"
    lines: list[str] = []
    for line in source.split(newline):
        # A trailing `_` continues a statement on the next line: parse the
        # logical line, and keep the break as a marker to restore on output.
        if lines and _continues(lines[-1]):
            lines[-1] += _JOIN + line
        else:
            lines.append(line)
    stmts = _statements(lines)
    pairs, orphans = _pairs(stmts)

    # SUB/DEF FN bodies are separate scopes: a pair crossing one is broken.
    scopes = [p for p in pairs if p.kind in ("SUB", "DEF")]
    broken: set[int] = set()
    for p in pairs:
        if p.kind in ("SUB", "DEF"):
            continue
        for s in scopes:
            if (p.open < s.open < p.close) or (p.open < s.close < p.close) or (
                s.open < p.open < s.close and not s.open < p.close < s.close
            ):
                broken.add(id(p))
    pairs = [p for p in pairs if id(p) not in broken or not orphans.extend([p.open, p.close])]

    flatten: set[int] = set()
    changed = True
    while changed:
        changed = False
        live = [p for p in pairs if id(p) not in flatten]
        for a in live:
            for b in live:
                if a is b or not _crosses(a, b):
                    continue
                victim = a if _COST[a.kind] <= _COST[b.kind] else b
                if _COST[victim.kind] >= 100:
                    # Two FOR loops (or a FOR and a scope) cross: give up on one.
                    orphans.extend([victim.open, victim.close])
                    pairs.remove(victim)
                else:
                    flatten.add(id(victim))
                changed = True
                break
            if changed:
                break

    edits: dict[int, list[str] | str] = {}  # statement index -> replacement
    counter = [0]

    def label() -> str:
        counter[0] += 1
        return f"TBDC{counter[0]}"

    flattened: dict[str, int] = {}
    for p in pairs:
        if id(p) not in flatten:
            continue
        flattened[p.kind] = flattened.get(p.kind, 0) + 1
        if p.kind == "IF":
            _flatten_if(p, stmts, edits, label)
        elif p.kind in ("DO", "WHILE"):
            _flatten_loop(p, stmts, edits, label)
        elif p.kind == "SELECT":
            _flatten_select(p, stmts, edits, label)
    orphan_texts = []
    for i in sorted(set(orphans)):
        if 0 <= i < len(stmts) and i not in edits:
            s = stmts[i]
            text = re.sub(r"_\s*" + _JOIN, " ", s.text).replace(_JOIN, " ").strip()
            orphan_texts.append(text)
            edits[i] = [f"REM TBDC: {text}"]
    return Restructured(_apply(lines, stmts, edits, newline), flattened, orphan_texts)


def _cond(text: str, keyword: str) -> str:
    """The condition after ``keyword`` (IF/ELSEIF/WHILE/UNTIL...)."""

    plain = _strip_strings(text)
    m = re.search(rf"\b{keyword}\b", plain, re.IGNORECASE)
    rest = text[m.end() :] if m else ""
    t = re.search(r"\bTHEN\s*$", _strip_strings(rest), re.IGNORECASE)
    if t:
        rest = rest[: t.start()]
    return rest.strip()


def _flatten_if(p: Pair, stmts, edits, label) -> None:
    end = label()
    pending = label()
    edits[p.open] = [f"IF ({_cond(stmts[p.open].text, 'IF')}) = 0 THEN {pending}"]
    for m in p.middles:
        s = stmts[m]
        out = [f"GOTO {end}", f"{pending}:"]
        if s.kind == "ELSEIF":
            pending = label()
            out.append(f"IF ({_cond(s.text, 'ELSEIF')}) = 0 THEN {pending}")
        else:
            pending = ""
        edits[m] = out
    edits[p.close] = ([f"{pending}:"] if pending else []) + [f"{end}:"]


def _flatten_loop(p: Pair, stmts, edits, label) -> None:
    top, out = label(), label()
    head = stmts[p.open].text
    words = _words(head)
    first = [f"{top}:"]
    if p.kind == "WHILE":
        first.append(f"IF ({_cond(head, 'WHILE')}) = 0 THEN {out}")
    elif len(words) > 1 and words[1] == "WHILE":
        first.append(f"IF ({_cond(head, 'WHILE')}) = 0 THEN {out}")
    elif len(words) > 1 and words[1] == "UNTIL":
        first.append(f"IF {_cond(head, 'UNTIL')} THEN {out}")
    edits[p.open] = first
    tail = stmts[p.close].text
    words = _words(tail)
    if p.kind == "DO" and len(words) > 1 and words[1] == "WHILE":
        last = [f"IF {_cond(tail, 'WHILE')} THEN {top}"]
    elif p.kind == "DO" and len(words) > 1 and words[1] == "UNTIL":
        last = [f"IF ({_cond(tail, 'UNTIL')}) = 0 THEN {top}"]
    else:
        last = [f"GOTO {top}"]
    edits[p.close] = last + [f"{out}:"]
    for e in p.exits:
        edits[e] = f"GOTO {out}"


def _flatten_select(p: Pair, stmts, edits, label) -> None:
    head = stmts[p.open].text
    selector = re.sub(r"^\s*SELECT\s+CASE\s+", "", head, flags=re.IGNORECASE).strip()
    guards_text = " ".join(stmts[m].text for m in p.middles)
    is_str = '"' in selector or '"' in guards_text or bool(
        re.match(r"^[A-Za-z][A-Za-z0-9.]*\$", selector)
    )
    var = f"TBDCS{label()[4:]}" + ("$" if is_str else "#")
    end = label()
    edits[p.open] = [f"{var} = {selector}"]
    pending = ""
    for m in p.middles:
        s = stmts[m]
        guards = re.sub(r"^\s*CASE\s+", "", s.text, flags=re.IGNORECASE).strip()
        out = [f"GOTO {end}"] if pending or m != p.middles[0] else []
        if pending:
            out.append(f"{pending}:")
        if guards.upper() == "ELSE":
            pending = ""
        else:
            pending = label()
            tests = []
            for g in _split_commas(guards):
                gm = re.match(r"(?i)^IS\s*(<=|>=|<>|<|>|=)\s*(.*)$", g)
                to = _find_word(g, "TO")
                if gm:
                    tests.append(f"({var} {gm.group(1)} {gm.group(2)})")
                elif to is not None:
                    lo, hi = g[:to], g[to + 2 :]
                    tests.append(f"({var} >= {lo.strip()} AND {var} <= {hi.strip()})")
                else:
                    tests.append(f"({var} = {g})")
            out.append(f"IF ({' OR '.join(tests)}) = 0 THEN {pending}")
        edits[m] = out
    edits[p.close] = ([f"{pending}:"] if pending else []) + [f"{end}:"]


def _find_word(text: str, word: str) -> int | None:
    quoted = False
    for i, ch in enumerate(text):
        if ch == '"':
            quoted = not quoted
        elif not quoted and text[i : i + len(word)].upper() == word:
            before = text[i - 1] if i else " "
            after = text[i + len(word)] if i + len(word) < len(text) else " "
            if not (before.isalnum() or after.isalnum() or after in "%&!#$"):
                return i
    return None


def _split_commas(text: str) -> list[str]:
    parts, depth, quoted, start = [], 0, False, 0
    for i, ch in enumerate(text):
        if ch == '"':
            quoted = not quoted
        elif not quoted:
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
            elif ch == "," and depth == 0:
                parts.append(text[start:i].strip())
                start = i + 1
    parts.append(text[start:].strip())
    return [p for p in parts if p]


def _apply(lines: list[str], stmts: list[Stmt], edits: dict, newline: str) -> str:
    by_line: dict[int, list[tuple[Stmt, list[str] | str]]] = {}
    for i, rep in edits.items():
        by_line.setdefault(stmts[i].line, []).append((stmts[i], rep))
    out: list[str] = []
    for index, line in enumerate(lines):
        if index not in by_line:
            out.append(line)
            continue
        items = sorted(by_line[index], key=lambda x: x[0].start, reverse=True)
        whole = [it for it in items if isinstance(it[1], list)]
        if whole and len(items) == 1 and items[0][0].sole:
            s, rep = items[0]
            m = _NUMBER.match(line)
            prefix = line[: s.start]
            indent = re.match(r"\s*", line[s.start :]).group(0) if not m else ""
            first = True
            for r in rep:
                if r.endswith(":") and _LABEL.match(r):
                    if first and m:
                        out.append(prefix + "REM")  # keep the line number as a target
                    out.append(r)
                elif first:
                    out.append(prefix + indent + r if m else (re.match(r"\s*", line).group(0) + r))
                else:
                    out.append((re.match(r"\s*", line).group(0) if not m else "") + r)
                first = False
            continue
        # Statements inside a multi-statement line: rewrite in place.
        text = line
        trailing_labels: list[str] = []
        for s, rep in items:
            if isinstance(rep, str):
                text = text[: s.start] + " " + rep + text[s.end :]
                continue
            code = [r for r in rep if not (_LABEL.match(r) and r.endswith(":"))]
            labels = [r for r in rep if _LABEL.match(r) and r.endswith(":")]
            text = text[: s.start] + " " + (": ".join(code) if code else "REM") + text[s.end :]
            trailing_labels.extend(labels)
        out.append(text)
        out.extend(trailing_labels)
    return newline.join(out).replace(_JOIN, newline)


_GOTO_ONLY = re.compile(r"^\s*GOTO\s+[A-Za-z0-9.]+\s*$", re.IGNORECASE)


def drop_after_goto(source: str) -> tuple[str, int]:
    """Remove statements that follow a GOTO on the same line.

    They can never run, and Turbo Basic rejects them ("End-of-line expected").
    """

    newline = "\r\n" if "\r\n" in source else "\n"
    lines = source.split(newline)
    dropped = 0
    for index, line in enumerate(lines):
        if ":" not in line or "GOTO" not in line.upper():
            continue
        spans = _split_statements(line)
        if len(spans) < 2:
            continue
        for k, (a, b) in enumerate(spans[:-1]):
            piece = line[a:b]
            if k == 0:
                piece = _NUMBER.sub(r"\1", piece)
                inline = _inline_if(piece)
                # `IF c THEN GOTO n: ...` -- the GOTO is the clause's last word
                tail = piece[inline[1][-1][0] :] if inline else piece
                if inline and len(inline[1]) > 1:
                    continue  # the clause has an ELSE: leave the line alone
            else:
                tail = piece
            if _GOTO_ONLY.match(tail):
                rest = line[b:]
                comment = re.search(r"'", rest)
                lines[index] = line[:b] + (rest[comment.start() :] if comment and rest[: comment.start()].count('"') % 2 == 0 else "")
                dropped += 1
                break
    return newline.join(lines), dropped
