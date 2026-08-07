"""Canonical Turbo Basic source emitter: typed IR statements -> recompilable text.

Identifier names and line numbers contribute zero bytes to the compiled image,
so the emitter canonicalizes freely: one statement per line, numbered 10, 20,
...; variables arrive already canonically named (A, B, ...) by the decoder in
first-store order.

IDE compiler toggles (decode0.Program.toggles) are deliberately NOT emitted.
They have no source spelling, and -- unlike a metastatement, whose source line
regenerates its bytes -- a `'`-comment carrying them would not be
byte-invisible: with Keyboard break or Overflow checking enabled, comment text
perturbs a program-dependent runtime table (witnessed by the fkb_t1_and corpus
fixture). The emitted source therefore stays exactly what recompiles
byte-identically; the toggles ride on Program.toggles and the CLI reports them
out-of-band.
"""

from dataclasses import dataclass
import re

from tbx import ir

#: "The Turbo Basic editor supports lines up to 248 characters wide" (Owner's
#: Handbook, 1987). A wider physical line is not source the compiler could ever
#: have been handed, so emitting one means the emitter has not produced source
#: -- however well it would recompile in principle. Wild zip.exe is the
#: witness: 295 characters of reconstructed DATA, and the oracle harness never
#: got it into the editor to compile at all.
LINE_LIMIT = 248
#: The integrated editor cannot load a source file larger than 64 KiB. Keep
#: one byte spare so every generated file is strictly below that boundary.
FILE_LIMIT = 65535
#: The compiler rejects a 64 KiB include with Error 495 even though the editor
#: accepts a root BAS up to 64 KiB. Keep includes below the signed-word boundary.
INCLUDE_LIMIT = 32767
#: A GOTO/GOSUB target past this silently fails to compile (Error 417: Label
#: / line number expected) even though the same number as a bare, unreferenced
#: label is accepted -- probed empirically: 65530 compiles as a jump target,
#: 65535 and 65536 do not. Keep well clear of that boundary rather than
#: chase its exact value. Wild k.exe (24340 statements) is the witness: the
#: free stride-10 renumbering below reaches into the 200,000s for a program
#: this size, which no jump into that range can actually reach.
MAX_LINE_NUMBER = 65529


@dataclass(frozen=True)
class SourceBundle:
    """One root BAS plus source-relative include files."""

    root: str
    includes: tuple[tuple[str, str], ...] = ()


_PROC_HEADER = re.compile(r"^\d+ (?:SUB\b|DEF FN)")


def _source_bytes(text: str) -> int:
    """Size as Turbo Basic reads it: emitted source is an 8-bit byte stream."""
    try:
        return len(text.encode("latin-1"))
    except UnicodeEncodeError as exc:
        raise ValueError("emitted source contains a non-Latin-1 character") from exc


def _compact_source_spacing(source: str) -> str:
    """Remove optional spaces outside string literals.

    Turbo Basic requires indentation for scanned procedure/block bodies, so
    compact output retains one leading space per nesting level. Spaces around
    `=` and after list separators are lexical decoration and can be removed.
    """
    out = []
    for line in source.splitlines(keepends=True):
        parts = re.split(r'("[^"]*")', line)
        for i in range(0, len(parts), 2):
            parts[i] = re.sub(r" *= *", "=", parts[i])
            parts[i] = re.sub(r"([,;]) +", r"\1", parts[i])
            parts[i] = re.sub(r" *\+ *", "+", parts[i])
        out.append("".join(parts))
    return "".join(out)


def _all_source_includes(
    source: str, clean: str, root_limit: int, include_limit: int
) -> SourceBundle:
    """Pack complete physical BASIC lines; root contains only includes.

    Never cuts inside an open block construct (IF/DO/WHILE/SELECT CASE): a
    nested body line is rendered indented (`block_lines`' 2-space-per-level
    convention), so a line with no leading whitespace is the only place a
    cut can happen without splitting a block's scope across two files.
    Deferring past the byte limit until the next top-level line is safe --
    wild k.exe is the witness a cut that doesn't defer isn't: Turbo Basic's
    own compiler desyncs many statements later in the file once a block's
    body has been torn across an $INCLUDE boundary, surfacing as an
    unrelated-looking syntax error far from the real cause.
    """
    chunks: list[str] = []
    pending: list[str] = []
    size = 0
    for line in source.splitlines(keepends=True):
        line_size = _source_bytes(line)
        if line_size > include_limit:
            raise ValueError(
                f"one physical source line is {line_size} bytes; "
                f"no line-boundary split fits the {include_limit}-byte limit"
            )
        at_top_level = line == line.lstrip()
        if pending and size + line_size > include_limit and at_top_level:
            chunks.append("".join(pending))
            pending = []
            size = 0
        pending.append(line)
        size += line_size
    if pending:
        chunks.append("".join(pending))
    if len(chunks) > 999:
        raise ValueError("more than 999 include files are required")
    includes = tuple(
        (f"{clean}{i:03d}.INC", text)
        for i, text in enumerate(chunks, 1)
    )
    root = "".join(f'$INCLUDE "{name}"\n' for name, _ in includes)
    if _source_bytes(root) > root_limit:
        raise ValueError(
            f"root source remains {_source_bytes(root)} bytes after "
            "line-boundary splitting"
        )
    return SourceBundle(root, includes)


def split_source(
    source: str,
    prefix: str = "TBX",
    limit: int = FILE_LIMIT,
    include_limit: int | None = None,
    force: bool = False,
) -> SourceBundle:
    """Split a procedure-free program into physical-line include chunks.

    The input is already fully rendered. Splitting that text, instead of
    rendering statement subsets, preserves global line numbering, BodyLine
    targets, line-table grouping, and metastatement placement exactly. Turbo
    Basic rejects `$INCLUDE` in a compilation unit containing scanned SUB or
    block DEF FN declarations, so that case fails loudly.
    """
    if limit < 1:
        raise ValueError("source-file limit must be positive")
    include_limit = min(limit, INCLUDE_LIMIT) if include_limit is None else include_limit
    if include_limit < 1:
        raise ValueError("include-file limit must be positive")
    if not force and _source_bytes(source) <= limit:
        return SourceBundle(source)
    if any(
        _PROC_HEADER.match(line)
        and not (" DEF FN" in line and " = " in line)
        for line in source.splitlines()
    ):
        raise ValueError(
            "cannot split source containing SUB or block DEF FN declarations: "
            "Turbo Basic rejects $INCLUDE with scanned statements"
        )
    clean = re.sub(r"[^A-Z0-9]", "", prefix.upper())[:5] or "TBX"
    return _all_source_includes(source, clean, limit, include_limit)


def emit_split(stmts, prefix: str = "TBX", force: bool = False) -> SourceBundle:
    """Render and split only when the 64 KiB editor limit requires it."""
    source = emit(stmts)
    if _source_bytes(source) > FILE_LIMIT and any(
        isinstance(stmt, (ir.SubDef, ir.DefFn)) and (
            not isinstance(stmt, ir.DefFn) or stmt.is_block
        )
        for stmt in stmts
    ):
        compact = emit(stmts, compact=True)
        if _source_bytes(compact) <= FILE_LIMIT:
            return SourceBundle(compact)
    return split_source(source, prefix=prefix, force=force)


def _split_list_statement(stmt, width: int):
    """A splittable list whose items do not fit one line, as several statements.

    DATA and COMMON are declarations for which the compiler is lossy about
    source statement boundaries; DATA is folded with `_` continuations so a
    width split does not invent extra codeless statements. A semicolon-separated PRINT list is likewise
    emitted as the same sequence of runtime item calls whether divided across
    physical PRINT statements (v10_t1_printphysical). So the division is the
    emitter's to choose, and it has to choose one that fits.

    Only the first statement is numbered by the caller; the rest are
    continuation lines, which keeps a `RESTORE` targeting this DATA pointing at
    the line it always did.

    Returns None when the statement is not a list of this kind or already fits.
    """
    if isinstance(stmt, ir.Data):
        # DATA's source statement boundary is byte-significant in the error
        # line table.  Physical `DATA ...` continuation lines are joined by
        # the compiler, whereas emitting each width-sized chunk as a new DATA
        # statement creates one codeless line-table entry per chunk.  Keep the
        # declaration logical and fold only its physical spelling.
        rendered = [ir.unparse_stmt(ir.Data((item,))).removeprefix("DATA ")
                    for item in stmt.items]
        return _wrap_continued("DATA ", rendered, width)
    elif isinstance(stmt, ir.Common):
        items, rebuild = stmt.names, lambda part: ir.Common(tuple(part))
    elif (
        isinstance(stmt, ir.Print)
        and stmt.commas is None
        and len(stmt.items) > 1
    ):
        # Consecutive semicolon-separated PRINT calls are byte-equivalent to
        # one long PRINT item list; in fact number.exe's repeated error-line
        # entry proves its 1063-column display was authored as several
        # physical PRINT lines. Every intermediate chunk suppresses its
        # newline, and the final chunk inherits the original terminator.
        items = stmt.items

        def rebuild(part):
            return ir.Print(tuple(part), newline=False, file=stmt.file)
    else:
        return None

    lines, part = [], []
    for item in items:
        candidate = part + [item]
        rendered = ir.unparse_stmt(rebuild(candidate))
        # The number prefix rides on the first line only.
        if part and len(rendered) + (width if not lines else 0) > LINE_LIMIT:
            lines.append(ir.unparse_stmt(rebuild(part)))
            part = [item]
        else:
            part = candidate
    if part:
        lines.append(ir.unparse_stmt(rebuild(part)))
    if isinstance(stmt, ir.Print) and lines:
        lines[-1] = ir.unparse_stmt(
            ir.Print(tuple(part), newline=stmt.newline, file=stmt.file)
        )
    # A single item too wide for a line on its own cannot be divided further;
    # say so rather than emitting a line the editor would reject.
    if len(lines) < 2:
        return None
    return "\n".join(lines)


def _name_fn_results(body, name):
    """Rewrite a DEF FN body's `FnResult`s into `NAME = value` at ANY nesting
    depth, as an ordinary `Assign` so the existing rendering handles them.

    `render_fn_body` above only substitutes the name for a result sitting at the
    body's TOP level; a nested one falls through to `unparse_stmt`, whose
    `FnResult` fallback is the placeholder `FN = ...` -- not valid source.
    Nested results only became reachable once a LITERAL result store stopped
    being swallowed as the prologue's result-slot init: wild tbd73.exe's
    `DEF FNCurdisplay` assigns its result inside five levels of block IF
    (t1_fnblockif).
    """
    out = []
    for b in body:
        if isinstance(b, ir.FnResult):
            out.append(ir.Assign(ir.Var(name), b.value))
        elif isinstance(b, ir.IfInline):
            out.append(
                ir.IfInline(
                    b.cond,
                    tuple(_name_fn_results(b.body, name)),
                    None
                    if b.else_body is None
                    else tuple(_name_fn_results(b.else_body, name)),
                )
            )
        elif isinstance(b, ir.IfBlock):
            out.append(
                ir.IfBlock(
                    tuple(
                        (c, tuple(_name_fn_results(arm, name))) for c, arm in b.arms
                    ),
                    None
                    if b.else_body is None
                    else tuple(_name_fn_results(b.else_body, name)),
                )
            )
        else:
            out.append(b)
    return out


def _join_line(group, txt, col: int) -> str:
    """Render one original line's statements, `:`-joined -- except after an IfGoto.

    Turbo Basic ends a line at an `IF ... THEN <line>`: `IF c THEN 80: S` is
    Error 431, End-of-line expected. So a statement the line table puts on the
    same line as an IfGoto can only have come from that IF's ELSE clause -- the
    fall-through path, which is exactly what IfGoto leaves to the next
    statement. Everything after the ELSE belongs to it, so the tail is joined
    the same way, nesting a further IfGoto inside the clause it falls into.
    Witnessed on wild vhfprop.exe (28 such lines).
    """
    head = txt(group[0], col)
    if len(group) == 1:
        return head
    tail = _join_line(group[1:], txt, col)
    sep = " ELSE " if isinstance(group[0], ir.IfGoto) else ": "
    return f"{head}{sep}{tail}"


def _wrap_continued(head: str, items: list[str], col: int) -> str:
    """`head` + comma list, folded over physical lines with `_` continuations.

    Turbo Basic joins a line ending in ` _` to the next one before compiling,
    and the result is byte-identical to the unwrapped spelling. Continuation
    lines are indented to the caller's margin so the statement still reads as
    one thing.
    """
    pad = " " * (col + 2)
    lines: list[str] = []
    cur = head
    first = True
    for i, item in enumerate(items):
        piece = item + ("," if i < len(items) - 1 else "")
        candidate = cur + ("" if cur.endswith(" ") or not cur else " ") + piece
        width = (0 if first else len(pad)) + len(candidate) + 2  # room for ` _`
        if not first or col:
            width += col if first else 0
        if cur not in (head, "") and width > LINE_LIMIT:
            lines.append(cur.rstrip() + " _")
            cur = pad + piece
            first = False
            continue
        cur = candidate if cur != head else head + piece
    lines.append(cur.rstrip())
    return "\n".join(lines)


def emit(stmts, *, compact: bool = False, line_starts: list[int] | None = None) -> str:
    def validate_loop_exits(body, do_depth=0, path=()):
        """Reject EXIT LOOP nodes that are not lexically inside a DO."""
        for index, stmt in enumerate(body):
            location = path + (index,)
            if isinstance(stmt, ir.Do):
                do_depth += 1
                continue
            if isinstance(stmt, ir.Loop):
                do_depth = max(0, do_depth - 1)
                continue
            if isinstance(stmt, ir.ExitLoop) and do_depth == 0:
                raise ValueError(
                    "EXIT LOOP without an enclosing DO "
                    f"at statement path {location}"
                )
            if isinstance(stmt, ir.IfInline):
                validate_loop_exits(stmt.body, do_depth, location + ("then",))
                if stmt.else_body is not None:
                    validate_loop_exits(stmt.else_body, do_depth, location + ("else",))
            elif isinstance(stmt, ir.IfBlock):
                for arm, (_, arm_body) in enumerate(stmt.arms):
                    validate_loop_exits(arm_body, do_depth, location + ("arm", arm))
                if stmt.else_body is not None:
                    validate_loop_exits(stmt.else_body, do_depth, location + ("else",))
            elif isinstance(stmt, ir.SelectCase):
                for arm, case in enumerate(stmt.arms):
                    validate_loop_exits(case.body, do_depth, location + ("case", arm))
                if stmt.case_else is not None:
                    validate_loop_exits(stmt.case_else, do_depth, location + ("case-else",))
            elif isinstance(stmt, ir.SubDef):
                validate_loop_exits(stmt.body, 0, location + ("sub",))
            elif isinstance(stmt, ir.DefFn) and stmt.is_block:
                validate_loop_exits(stmt.body, 0, location + ("def",))

    validate_loop_exits(stmts)

    # Jump targets INSIDE a SUB/DEF FN body (ir.BodyLine): physical line k of
    # the block at top-level index i is numbered line[i] + k, and only that
    # targeted line is emitted numbered (witnessed t1_subgsb).
    def flat(v):
        if isinstance(v, tuple):
            for x in v:
                yield from flat(x)
        else:
            yield v

    body_targets: set[tuple[int, int]] = set()
    end_sub_lines: dict[int, int] = {}

    def scan(n):
        for f in getattr(n, "__dataclass_fields__", ()):
            for item in flat(getattr(n, f)):
                if isinstance(item, ir.BodyLine):
                    body_targets.add((item.stmt, item.phys))
                elif hasattr(item, "__dataclass_fields__"):
                    scan(item)

    for s in stmts:
        scan(s)

    # Line numbers are normally free (renumber 10, 20, ...), EXCEPT when the image
    # embeds the error-trap line table (decode0.Program.lines): its entries store
    # the real line numbers, so the originals must be preserved to round-trip.
    orig = getattr(stmts, "lines", None)
    if orig is not None and len(orig) > 1 and len(set(orig)) <= 1:
        # A table whose entries are all the same number distinguishes nothing,
        # and cannot be the source's numbering: statements sharing a line are
        # grouped onto it, and 1789 of them do not fit 248 characters. Reading
        # it as real put the whole of wild metric.exe on one 43759-character
        # line the editor could not load. Treated as absent, so the statements
        # are renumbered the way a program carrying no table at all is -- which
        # compiles, where the grouped spelling could not be compiled to be
        # judged. All 52 corpus fixtures with a table have a real one.
        orig = None
    if orig is not None:
        line = {i: ln for i, ln in enumerate(orig)}
    else:
        # A statement with a deep BodyLine target (a numbered nested-IF
        # interior, wild inv87.exe) needs more than the canonical 10-line
        # gap to its own next statement's number -- widen just that gap to
        # fit the deepest phys reaching into it, instead of a flat stride.
        max_phys: dict[int, int] = {}
        for stmt, phys in body_targets:
            if phys > max_phys.get(stmt, 0):
                max_phys[stmt] = phys

        def _number(stride: int) -> tuple[dict[int, int], int]:
            numbering, cur = {}, 10
            for i in range(len(stmts)):
                numbering[i] = cur
                cur += max(stride, max_phys.get(i, 0) + 1)
            return numbering, cur

        # The default stride is 10, purely for readability -- shrink it only
        # when that would push a line number past MAX_LINE_NUMBER. A smaller
        # uniform stride is still widened per-statement to fit any BodyLine
        # target's own required gap, so nested-target correctness is
        # unaffected; this only ever changes cosmetic spacing between lines.
        line, final = _number(10)
        if final > MAX_LINE_NUMBER:
            stride = max(1, MAX_LINE_NUMBER // max(1, len(stmts)))
            line, final = _number(stride)
            if final > MAX_LINE_NUMBER:
                raise ValueError(
                    f"{len(stmts)} statements need line numbers up to {final} "
                    f"even at a 1-per-line stride, past Turbo Basic's real "
                    f"GOTO/GOSUB target ceiling ({MAX_LINE_NUMBER})"
                )

    def jump_indices(node):
        if isinstance(node, (ir.Goto, ir.IfGoto, ir.Gosub)):
            if isinstance(node.target, int):
                yield node.target
        elif isinstance(node, (ir.Return, ir.OnError, ir.Resume)):
            if isinstance(node.target, int):
                yield node.target
        elif isinstance(node, (ir.OnGoto, ir.OnGosub)):
            yield from (target for target in node.targets if isinstance(target, int))
        elif isinstance(node, ir.OnTrap) and isinstance(node.target, int):
            yield node.target
        for field in getattr(node, "__dataclass_fields__", ()):
            value = getattr(node, field)
            if isinstance(value, tuple):
                for item in value:
                    if hasattr(item, "__dataclass_fields__"):
                        yield from jump_indices(item)
            elif hasattr(value, "__dataclass_fields__"):
                yield from jump_indices(value)

    # Apply the INLINE-SUB return-label adjustment before any statement is
    # rendered.  Doing this lazily from L() makes an earlier ON ERROR target
    # retain the pre-shift line number (CVT2TB's handler exposes that mismatch).
    for target in set(target for stmt in stmts for target in jump_indices(stmt)):
        if (
            target > 0
            and target < len(stmts)
            and isinstance(stmts[target - 1], ir.SubDef)
            and len(stmts[target - 1].body) == 1
            and isinstance(stmts[target - 1].body[0], (ir.Inline, ir.OpaqueHelper))
        ):
            previous_sub = next(
                (
                    i
                    for i in range(target - 2, -1, -1)
                    if isinstance(stmts[i], ir.SubDef)
                ),
                None,
            )
            if previous_sub is not None and previous_sub not in end_sub_lines:
                target_line = line[target - 1]
                for index in range(target - 1, len(stmts)):
                    line[index] += 10
                end_sub_lines[previous_sub] = target_line

    def L(t):
        if isinstance(t, ir.BodyLine):
            nxt = line.get(t.stmt + 1)
            if nxt is not None and line[t.stmt] + t.phys >= nxt:
                raise ValueError(
                    f"body-line target {t} does not fit the line-number gap"
                )
            return line[t.stmt] + t.phys
        # A procedure return immediately before an INLINE SUB is represented
        # by the next executable procedure address after the opaque inline
        # body.  Turbo Basic source targets the numbered INLINE SUB line
        # itself, which is the compiler's skip label for that return boundary
        # (CVT2TB's outer guard is the witness).
        if (
            isinstance(t, int)
            and t > 0
            and isinstance(stmts[t - 1], ir.SubDef)
            and len(stmts[t - 1].body) == 1
            and isinstance(stmts[t - 1].body[0], (ir.Inline, ir.OpaqueHelper))
        ):
            previous_sub = next(
                (
                    i
                    for i in range(t - 2, -1, -1)
                    if isinstance(stmts[i], ir.SubDef)
                ),
                None,
            )
            if previous_sub is not None:
                # Leave the INLINE SUB on its own canonical line and put the
                # target label on the preceding procedure's END SUB line.
                # Shift the inline tail first, otherwise the new END SUB label
                # would sort before the preceding statements (CVT2TB).
                return end_sub_lines.get(previous_sub, line[t - 1])
            return line[t - 1]
        return line[t]

    def block_lines(body, render, col=0):
        """Indent each body statement two spaces; multi-line statements indent every line."""
        out = []
        for b in body:
            for ln in render(b, col + 2).split("\n"):
                out.append((" " if compact else "  ") + ln)
        return "\n".join(out)

    def txt(s, col=0):
        """One statement as source. `col` is the left margin it starts at.

        The margin is carried so a statement can tell whether its own widest
        spelling fits `LINE_LIMIT` -- the indent of the block it sits in counts
        against the same 248 characters the editor allows.
        """
        if isinstance(s, ir.Goto):
            return f"GOTO {L(s.target)}"
        if isinstance(s, ir.IfGoto):
            return f"IF {ir.unparse_cond(s.cond)} THEN {L(s.target)}"
        if isinstance(s, ir.Gosub):
            return f"GOSUB {L(s.target)}"
        if isinstance(s, ir.Return) and s.target is not None:
            return f"RETURN {L(s.target)}"
        if isinstance(s, (ir.OnGoto, ir.OnGosub)):
            kw = "GOTO" if isinstance(s, ir.OnGoto) else "GOSUB"
            head = f"ON {ir.unparse(s.selector)} {kw} "
            targets = [str(L(t)) for t in s.targets]
            out = head + ", ".join(targets)
            if col + len(out) <= LINE_LIMIT:
                return out
            # Too wide for the editor, so fold it over physical lines with
            # Turbo Basic's `_` continuation, which is byte-identical to the
            # one-line spelling (probe probe_on_gosub_continuation). An ON
            # GOSUB list is a single statement with nothing
            # `_split_list_statement` can divide, so this is the only lever --
            # wild help.exe's 56 targets are 364 characters on one line.
            return _wrap_continued(head, targets, col)
        if isinstance(s, ir.OnError):
            return f"ON ERROR GOTO {0 if s.target is None else L(s.target)}"
        if isinstance(s, ir.OnTrap):
            n = "" if s.n is None else f"({ir.unparse(s.n)})"
            return f"ON {s.event}{n} GOSUB {L(s.target)}"
        if isinstance(s, ir.Resume) and s.target is not None:
            return f"RESUME {L(s.target)}"
        if isinstance(s, ir.Restore) and s.target is not None:
            return f"RESTORE {L(s.target)}"
        if isinstance(s, ir.While):
            return f"WHILE {ir.unparse_cond(s.cond)}"
        if isinstance(s, ir.IfInline):
            body = ": ".join(txt(b, col) for b in s.body)
            inline = f"IF {ir.unparse_cond(s.cond)} THEN {body}"
            if s.else_body:
                # The ELSE form has no block equivalent to fall back on: over a
                # simple condition the two compile differently, so this stays
                # one line however wide it gets (t1_selarmifelse).
                tail = ": ".join(txt(b, col) for b in s.else_body)
                return f"{inline} ELSE {tail}"
            if col + len(inline) > LINE_LIMIT and isinstance(s.cond, ir.LogOp):
                # Too wide for the editor, and a compound condition -- for
                # which the block spelling compiles to the same bytes, checked
                # against the oracle on t1_ifin and t1_orrel. So the two are
                # the emitter's to choose between, and only one of them is
                # source Turbo Basic would accept. A simple condition is not
                # interchangeable (its inline form does not materialize, which
                # is what `decode0`'s `block_ifs` turns on) and stays as it is.
                return txt(ir.IfBlock(((s.cond, tuple(s.body)),), None), col)
            return inline
        if isinstance(s, ir.IfBlock):
            out = []
            for j, (cond, body) in enumerate(s.arms):
                out.append(
                    f"{'IF' if j == 0 else 'ELSEIF'} {ir.unparse_cond(cond)} THEN"
                )
                out.append(block_lines(body, txt, col))
            if s.else_body is not None:
                out.append("ELSE")
                out.append(block_lines(s.else_body, txt, col))
            out.append("END IF")
            return "\n".join(out)
        if isinstance(s, ir.SelectCase):
            out = [f"SELECT CASE {ir.unparse(s.selector)}"]
            for arm in s.arms:
                guards = ", ".join(ir.unparse_case_guard(g) for g in arm.guards)
                out.append(f"CASE {guards}")
                out.append(block_lines(arm.body, txt, col))
            if s.case_else is not None:
                out.append("CASE ELSE")
                out.append(block_lines(s.case_else, txt, col))
            out.append("END SELECT")
            return "\n".join(out)
        if isinstance(s, ir.SubDef):
            is_inline = len(s.body) == 1 and isinstance(
                s.body[0], (ir.Inline, ir.OpaqueHelper)
            )
            header = f"SUB {s.name} INLINE" if is_inline else f"SUB {s.name}{ir.params_sig(s.params)}"
            inner = block_lines(s.body, txt, col)
            return f"{header}\nEND SUB" if not inner else f"{header}\n{inner}\nEND SUB"
        if isinstance(s, ir.DefFn) and s.is_block:
            header = f"DEF {s.name}{ir.params_sig(s.params)}"

            def render_fn_body(b, col=0):
                # FnResult carries no name; render with this DEF FN's name as `NAME = v`.
                if isinstance(b, ir.FnResult):
                    return f"{s.name} = {ir.unparse(b.value)}"
                return txt(b, col)

            inner = block_lines(
                _name_fn_results(s.body, s.name), render_fn_body, col
            )
            return f"{header}\nEND DEF" if not inner else f"{header}\n{inner}\nEND DEF"
        if isinstance(s, ir.Dim):
            out = ir.unparse_stmt(s)
            if col + len(out) <= LINE_LIMIT:
                return out
            # A DIM comma list is one statement with one trailing commit marker
            # (ir.Dim), unlike DATA/COMMON where the compiler is lossy about
            # where a list was divided -- so it cannot be split into several
            # DIM statements the way `_split_list_statement` divides those.
            # Turbo Basic's `_` continuation folds it over physical lines
            # without changing the statement boundary, and compiles
            # byte-identical (checked against the oracle on a 3-array DIM,
            # folded vs. unfolded). Wild d-fix.exe's 30-array DIM is 296 chars.
            head = "DIM DYNAMIC " if s.dynamic else "DIM "
            arrs = [
                ir.unparse_stmt(ir.Dim(n, b, dynamic=s.dynamic)).removeprefix(head)
                for n, b in ((s.name, s.bounds), *s.also)
            ]
            return _wrap_continued(head, arrs, col)
        return ir.unparse_stmt(s)

    # Statements sharing an original line number (only possible when the error-trap
    # line table supplied `orig`) are re-grouped onto one `:`-joined line.
    # Metastatements (decode0.Program.metas: (stmt_index, text) pairs) are
    # compile-time pragmas, not statements: each renders as an unnumbered line
    # immediately before its indexed statement ($STACK/$SOUND at 0, $EVENT
    # ON/OFF at region boundaries).
    pre: dict[int, list[str]] = {}
    for idx, m in getattr(stmts, "metas", ()):
        pre.setdefault(idx, []).append(m)
    # TRON trace hooks are per PHYSICAL LINE: inside a traced statement every
    # physical line -- block bodies, ELSE, even code-less END IF -- consumes the
    # next hook line and is emitted numbered (t1_tronif/t1_troncase). Untraced
    # blocks keep the unnumbered indented style.
    hooks = list(getattr(stmts, "hook_seq", ()) or ())
    traced = set(getattr(stmts, "traced", ()) or ())
    # A block whose TRON region ends mid-body traces only a leading run of physical
    # lines (t1_troffin): {stmt index -> count}. The traced prefix is numbered from the
    # hooks; the untraced tail (post-TROFF body + END IF) keeps the indented block style.
    partial = getattr(stmts, "trace_partial", {}) or {}
    out, i = [], 0
    while i < len(stmts):
        out.extend(f"{m}\n" for m in pre.get(i, []))
        j = i + 1
        while j < len(stmts) and line[j] == line[i]:
            j += 1
        if line_starts is not None:
            # 0-based index into the final source text of the first physical
            # line this statement (or this line-grouped run of statements,
            # e.g. "10 A=1:B=2") renders to. Statements sharing a line get
            # the same start, matching how they're indistinguishable in the
            # emitted text.
            start = sum(fragment.count("\n") for fragment in out)
            line_starts.extend([start] * (j - i))
        text = _join_line(
            [stmts[k] for k in range(i, j)], txt, len(f"{line[i]} ")
        )
        if i in end_sub_lines:
            physical = text.splitlines()
            physical[-1] = f"{end_sub_lines[i]} {physical[-1].strip()}"
            text = "\n".join(physical)
        if i in traced:
            body = text.split("\n")
            nt = partial.get(i, len(body))  # physical lines that carry a hook
            if len(hooks) < nt or hooks[0] != line[i]:
                raise ValueError(
                    "trace-hook lines misaligned with the traced "
                    "statement's physical lines"
                )
            nums, hooks = hooks[:nt], hooks[nt:]
            out.extend(f"{n} {ln.strip()}\n" for n, ln in zip(nums, body[:nt]))
            out.extend(f"{ln}\n" for ln in body[nt:])  # untraced tail keeps its indent
        elif any(t[0] in range(i, j) for t in body_targets):
            # a body physical line is a jump target: emit it numbered
            if j != i + 1:
                raise ValueError("body-line target in a line-grouped statement")
            body = text.split("\n")
            targeted = {k for (si, k) in body_targets if si == i}
            if not all(0 < k < len(body) for k in targeted):
                raise ValueError(f"body-line target out of range at stmt {i}")
            out.append(f"{line[i]} {body[0]}\n")
            out.extend(
                f"{line[i] + k} {ln.strip()}\n" if k in targeted else f"{ln}\n"
                for k, ln in enumerate(body[1:], 1)
            )
        else:
            prefix = f"{line[i]} "
            physical = text.splitlines() or [""]
            widths = [len(prefix) + len(physical[0])]
            widths.extend(len(part) for part in physical[1:])
            widest = max(widths)
            if j == i + 1 and widest > LINE_LIMIT:
                # Too wide for the editor. A list declaration can be divided
                # without changing what it compiles to. Optional expression
                # spacing is equally free, and is enough for long literal
                # concatenations (wild cal.exe/cal87.exe).
                divided = _split_list_statement(stmts[i], len(prefix))
                if divided is not None:
                    text = divided
                else:
                    narrowed = _compact_source_spacing(prefix + text)
                    if max(map(len, narrowed.splitlines())) <= LINE_LIMIT:
                        text = narrowed[len(prefix) :]
            out.append(f"{prefix}{text}\n")
        i = j
    if hooks:
        raise ValueError(f"{len(hooks)} trace-hook lines left unconsumed")
    source = "".join(out)
    return _compact_source_spacing(source) if compact else source
