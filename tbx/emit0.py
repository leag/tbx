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

from tbx import ir

#: "The Turbo Basic editor supports lines up to 248 characters wide" (Owner's
#: Handbook, 1987). A wider physical line is not source the compiler could ever
#: have been handed, so emitting one means the emitter has not produced source
#: -- however well it would recompile in principle. Wild zip.exe is the
#: witness: 295 characters of reconstructed DATA, and the oracle harness never
#: got it into the editor to compile at all.
LINE_LIMIT = 248


def _split_list_statement(stmt, width: int):
    """A DATA or COMMON whose items do not fit one line, as several statements.

    Both are declarations of a list, and the compiler is lossy about how the
    list was divided: `ir.Common`'s own note records that splitting across
    several COMMON statements compiles identically (t1_common1), and DATA items
    enter the constant pool in order, which several statements preserve exactly
    as one does. So the division is the emitter's to choose, and it has to
    choose one that fits.

    Only the first statement is numbered by the caller; the rest are
    continuation lines, which keeps a `RESTORE` targeting this DATA pointing at
    the line it always did.

    Returns None when the statement is not a list of this kind or already fits.
    """
    if isinstance(stmt, ir.Data):
        items, rebuild = stmt.items, lambda part: ir.Data(tuple(part))
    elif isinstance(stmt, ir.Common):
        items, rebuild = stmt.names, lambda part: ir.Common(tuple(part))
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
            out.append(ir.IfInline(b.cond, tuple(_name_fn_results(b.body, name))))
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

def emit(stmts) -> str:
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
        line = {}
        cur = 10
        for i in range(len(stmts)):
            line[i] = cur
            cur += max(10, max_phys.get(i, 0) + 1)

    def L(t):
        if isinstance(t, ir.BodyLine):
            nxt = line.get(t.stmt + 1)
            if nxt is not None and line[t.stmt] + t.phys >= nxt:
                raise ValueError(
                    f"body-line target {t} does not fit the line-number gap"
                )
            return line[t.stmt] + t.phys
        return line[t]

    def block_lines(body, render):
        """Indent each body statement two spaces; multi-line statements indent every line."""
        out = []
        for b in body:
            for ln in render(b).split("\n"):
                out.append("  " + ln)
        return "\n".join(out)

    def txt(s):
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
            lines = ", ".join(str(L(t)) for t in s.targets)
            return f"ON {ir.unparse(s.selector)} {kw} {lines}"
        if isinstance(s, ir.OnError):
            return f"ON ERROR GOTO {0 if s.target is None else L(s.target)}"
        if isinstance(s, ir.OnTrap):
            n = "" if s.n is None else f"({ir.unparse(s.n)})"
            return f"ON {s.event}{n} GOSUB {L(s.target)}"
        if isinstance(s, ir.Resume) and s.target is not None:
            return f"RESUME {L(s.target)}"
        if isinstance(s, ir.While):
            return f"WHILE {ir.unparse_cond(s.cond)}"
        if isinstance(s, ir.IfInline):
            body = ": ".join(txt(b) for b in s.body)
            return f"IF {ir.unparse_cond(s.cond)} THEN {body}"
        if isinstance(s, ir.IfBlock):
            out = []
            for j, (cond, body) in enumerate(s.arms):
                out.append(
                    f"{'IF' if j == 0 else 'ELSEIF'} {ir.unparse_cond(cond)} THEN"
                )
                out.append(block_lines(body, txt))
            if s.else_body is not None:
                out.append("ELSE")
                out.append(block_lines(s.else_body, txt))
            out.append("END IF")
            return "\n".join(out)
        if isinstance(s, ir.SelectCase):
            out = [f"SELECT CASE {ir.unparse(s.selector)}"]
            for arm in s.arms:
                guards = ", ".join(ir.unparse_case_guard(g) for g in arm.guards)
                out.append(f"CASE {guards}")
                out.append(block_lines(arm.body, txt))
            if s.case_else is not None:
                out.append("CASE ELSE")
                out.append(block_lines(s.case_else, txt))
            out.append("END SELECT")
            return "\n".join(out)
        if isinstance(s, ir.SubDef):
            is_inline = len(s.body) == 1 and isinstance(
                s.body[0], (ir.Inline, ir.OpaqueHelper)
            )
            header = f"SUB {s.name} INLINE" if is_inline else f"SUB {s.name}{ir.params_sig(s.params)}"
            inner = block_lines(s.body, txt)
            return f"{header}\nEND SUB" if not inner else f"{header}\n{inner}\nEND SUB"
        if isinstance(s, ir.DefFn) and s.is_block:
            header = f"DEF {s.name}{ir.params_sig(s.params)}"

            def render_fn_body(b):
                # FnResult carries no name; render with this DEF FN's name as `NAME = v`.
                if isinstance(b, ir.FnResult):
                    return f"{s.name} = {ir.unparse(b.value)}"
                return txt(b)

            inner = block_lines(_name_fn_results(s.body, s.name), render_fn_body)
            return f"{header}\nEND DEF" if not inner else f"{header}\n{inner}\nEND DEF"
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
        text = ": ".join(txt(stmts[k]) for k in range(i, j))
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
            if j == i + 1 and len(prefix) + len(text) > LINE_LIMIT:
                # Too wide for the editor. A list declaration can be divided
                # without changing what it compiles to; anything else has to
                # go out as it is, since narrowing it would be a guess about
                # source we did not recover.
                divided = _split_list_statement(stmts[i], len(prefix))
                if divided is not None:
                    text = divided
            out.append(f"{prefix}{text}\n")
        i = j
    if hooks:
        raise ValueError(f"{len(hooks)} trace-hook lines left unconsumed")
    return "".join(out)
