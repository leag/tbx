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


def emit(stmts) -> str:
    # Line numbers are normally free (renumber 10, 20, ...), EXCEPT when the image
    # embeds the error-trap line table (decode0.Program.lines): its entries store
    # the real line numbers, so the originals must be preserved to round-trip.
    orig = getattr(stmts, "lines", None)
    line = (
        {i: ln for i, ln in enumerate(orig)}
        if orig is not None
        else {i: 10 * (i + 1) for i in range(len(stmts))}
    )

    def block_lines(body, render):
        """Indent each body statement two spaces; multi-line statements indent every line."""
        out = []
        for b in body:
            for ln in render(b).split("\n"):
                out.append("  " + ln)
        return "\n".join(out)

    def txt(s):
        if isinstance(s, ir.Goto):
            return f"GOTO {line[s.target]}"
        if isinstance(s, ir.IfGoto):
            return f"IF {ir.unparse_cond(s.cond)} THEN {line[s.target]}"
        if isinstance(s, ir.Gosub):
            return f"GOSUB {line[s.target]}"
        if isinstance(s, (ir.OnGoto, ir.OnGosub)):
            kw = "GOTO" if isinstance(s, ir.OnGoto) else "GOSUB"
            lines = ", ".join(str(line[t]) for t in s.targets)
            return f"ON {ir.unparse(s.selector)} {kw} {lines}"
        if isinstance(s, ir.OnError):
            return f"ON ERROR GOTO {0 if s.target is None else line[s.target]}"
        if isinstance(s, ir.OnTrap):
            n = "" if s.n is None else f"({ir.unparse(s.n)})"
            return f"ON {s.event}{n} GOSUB {line[s.target]}"
        if isinstance(s, ir.Resume) and s.target is not None:
            return f"RESUME {line[s.target]}"
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
            header = f"SUB {s.name}{ir.params_sig(s.params)}"
            inner = block_lines(s.body, txt)
            return f"{header}\nEND SUB" if not inner else f"{header}\n{inner}\nEND SUB"
        if isinstance(s, ir.DefFn) and s.is_block:
            header = f"DEF {s.name}{ir.params_sig(s.params)}"

            def render_fn_body(b):
                # FnResult carries no name; render with this DEF FN's name as `NAME = v`.
                if isinstance(b, ir.FnResult):
                    return f"{s.name} = {ir.unparse(b.value)}"
                return txt(b)

            inner = block_lines(s.body, render_fn_body)
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
        else:
            out.append(f"{line[i]} {text}\n")
        i = j
    if hooks:
        raise ValueError(f"{len(hooks)} trace-hook lines left unconsumed")
    return "".join(out)
