"""DOS/OS statement handlers: filesystem, SHELL, device I/O, sound, timing, date.

Handlers for ``decode_user_code``'s dispatch loop; each handler takes
the shared :class:`~tbx.decode0.core.DecodeState` plus the current
``op``/``addr``/``kind`` and returns ``True`` when it consumed the op.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from tbx import ir
from tbx.decode0.matchers import match_delay

if TYPE_CHECKING:
    from tbx.decode0.core import DecodeState


def filesystem(state: DecodeState, op, addr, kind) -> bool:
    """DOS filesystem statements: KILL / FILES / NAME / CHDIR / MKDIR / RMDIR.

    Each takes its path/spec string(s) off ``sstack`` and emits the statement.
    Returns True when handled (the loop should ``continue``).
    """
    e, c = state.expr, state.control
    if kind == "kill":  # KILL file$
        state.put(ir.Kill(e.sstack.pop()), c.cur)
    elif kind == "files":  # FILES spec$
        state.put(ir.Files(e.sstack.pop()), c.cur)
    elif kind == "files_bare":  # FILES
        state.put(ir.Files(), c.cur)
    elif kind == "name":  # NAME old$ AS new$ (new pushed first)
        new, old = e.sstack.pop(), e.sstack.pop()
        state.put(ir.Name(old, new), c.cur)
    elif kind == "chdir":  # CHDIR path$ (EC sub 10)
        state.put(ir.Chdir(e.sstack.pop()), c.cur)
    elif kind == "mkdir":  # MKDIR path$ (EC sub 6A)
        state.put(ir.Mkdir(e.sstack.pop()), c.cur)
    elif kind == "rmdir":  # RMDIR path$ (EC sub C2)
        state.put(ir.Rmdir(e.sstack.pop()), c.cur)
    else:
        return False
    c.cur = None
    state.advance()
    return True


def _emit_os_statement(state: DecodeState, statement) -> bool:
    c = state.control
    state.put(statement, c.cur)
    c.cur = None
    state.advance()
    return True


def os_system(state: DecodeState, op, addr, kind) -> bool:
    """Dispatch family: shell, chain, environ, reset, randomize, clear, bload, bsave."""
    e = state.expr
    string_statements = {
        "shell": ir.Shell,
        "chain": ir.Chain,
        "run_file": ir.Run,
        "environ": ir.Environ,
    }
    if kind in string_statements:
        return _emit_os_statement(state, string_statements[kind](e.sstack.pop()))
    if kind == "reset":
        return _emit_os_statement(state, ir.Reset())
    if kind == "randomize":
        return _emit_os_statement(state, ir.Randomize(e.stack.pop()))
    if kind == "clear":
        return _emit_os_statement(state, ir.Clear())
    if kind == "bload":
        offset = e.stack.pop()
        return _emit_os_statement(state, ir.Bload(e.sstack.pop(), offset))
    if kind == "bload0":
        return _emit_os_statement(state, ir.Bload(e.sstack.pop()))
    if kind == "bsave":
        length = e.stack.pop()
        offset = e.stack.pop()
        return _emit_os_statement(state, ir.Bsave(e.sstack.pop(), offset, length))
    return False


def device_io(state: DecodeState, op, addr, kind) -> bool:
    """Dispatch family: out, out_imm, in_al, poke."""
    m, e, c = state.machine, state.expr, state.control
    if kind == "out_imm":
        state.put(ir.Out(ir.Lit(op[2]), ir.Lit(op[3])), c.cur)
        c.cur = None
        state.advance()
        return True
    if kind == "out":  # OUT port(dx), value(ax)
        state.put(ir.Out(m.dx, m.ax), c.cur)
        m.dx = m.ax = None
        c.cur = None
        state.advance()
        return True
    if kind == "in_al":  # ax = INP(port in dx)
        m.ax = ir.Call("INP", (m.dx,))
        m.dx = None
        state.advance()
        return True
    if kind == "poke":  # POKE addr(FP), value(ax)
        state.put(ir.Poke(e.stack.pop(), m.ax), c.cur)
        m.ax = None
        c.cur = None
        state.advance()
        return True
    return False


def devwait(state: DecodeState, op, addr, kind) -> bool:
    """Dispatch family: wait_poll, wait_poll3."""
    m, c = state.machine, state.control
    if kind == "wait_poll":  # WAIT port(dx), mask(bx)
        state.put(ir.Wait(m.dx, m.bx), c.cur)
        m.dx = m.bx = None
        c.cur = None
        state.advance()
        return True
    if kind == "wait_poll3":  # WAIT port(dx), and(cx), xor(bx)
        state.put(ir.Wait(m.dx, m.cx, m.bx), c.cur)
        m.dx = m.bx = m.cx = None
        c.cur = None
        state.advance()
        return True
    return False


def sound(state: DecodeState, op, addr, kind) -> bool:
    """Dispatch family: beep, sound, play."""
    m, e, c = state.machine, state.expr, state.control
    if kind == "beep":  # BEEP (zero operand)
        state.put(ir.Beep(), c.cur)
        c.cur = None
        state.advance()
        return True
    if kind == "sound":  # SOUND freq(ax), dur(FP stack)
        dur = e.stack.pop()
        if m.ax is None or isinstance(m.ax, tuple):
            raise ValueError(f"SOUND without a freq argument at {addr:#x}")
        state.put(ir.Sound(m.ax, dur), c.cur)
        m.ax = None
        c.cur = None
        state.advance()
        return True
    if kind == "play":  # PLAY music$
        state.put(ir.Play(e.sstack.pop()), c.cur)
        c.cur = None
        state.advance()
        return True
    return False


def timing(state: DecodeState, op, addr, kind) -> bool:
    """Dispatch family: delay_init, mtimer."""
    e, c, o = state.expr, state.control, state.output
    if kind == "delay_init":  # DELAY secs (FP) + poll loop tail
        secs = e.stack.pop()
        # Under active event trapping, a per-statement CC poll hook (q.v.
        # trap_hook's own generic handler) can land between delay_init and
        # delay_poll -- skip it here too (recording its addr into cc_hooks,
        # mirroring the generic path) rather than treating it as a template
        # break (wild prtguide.exe/readme.exe, both under ON TIMER/KEY
        # event trapping). A hook immediately BEFORE delay_poll also
        # re-stamps the loop's own back-jump onto the HOOK's address, not
        # delay_poll's (the same trace-hook quirk `_has_jmps_back` already
        # documents for WHILE loops): track that as the effective target.
        if state.cursor is None:
            raise state.error("DELAY matcher has no operation cursor", component="cursor")
        matched = match_delay(state.cursor)
        if matched is None:
            raise state.error(f"DELAY without poll op at {addr:#x}", component="control")
        for hook in matched.hooks:
            o.cc_hooks.add(hook[0])
        state.put(ir.Delay(secs), c.cur)
        c.cur = None
        state.advance(matched.stop - c.k)
        return True
    if kind == "mtimer":  # MTIMER (zero operand)
        state.put(ir.Mtimer(), c.cur)
        c.cur = None
        state.advance()
        return True
    return False


def datetime(state: DecodeState, op, addr, kind) -> bool:
    """Dispatch family: dateset, timeset."""
    e, c = state.expr, state.control
    if kind in ("dateset", "timeset"):  # DATE$/TIME$ = s$
        state.put(
            ir.DateTimeSet(
                "DATE$" if kind == "dateset" else "TIME$", e.sstack.pop()
            ),
            c.cur,
        )
        c.cur = None
        state.advance()
        return True
    return False


def segments(state: DecodeState, op, addr, kind) -> bool:
    """Dispatch family: defseg, defseg_set."""
    e, c = state.expr, state.control
    if kind == "defseg":  # bare DEF SEG: restore DS
        state.put(ir.DefSeg(None), c.cur)
        c.cur = None
        state.advance()
        return True
    if kind == "defseg_set":  # DEF SEG = <fp>
        state.put(ir.DefSeg(e.stack.pop()), c.cur)
        c.cur = None
        state.advance()
        return True
    return False


def bounds(state: DecodeState, op, addr, kind) -> bool:
    """Dispatch family: bchk0, bchk_span, bchk_base_bp, bchk_idx_bp."""
    m, e, l, c = state.machine, state.expr, state.layout_state, state.control
    if kind == "bchk0":  # Bounds: xor si,si starts a checked index; reset the
        e.bchk_subs = []  # pending non-final subscripts (F3.4/F3.5)
        e.bchk_bp = None
        state.advance()
        return True
    if kind == "bchk_base_bp":
        if (
            (c.proc_frame is None and c.fn_frame is None)
            or op[2] not in l.r_arrs
            or l.r_arrs[op[2]]["rank"] != 1
        ):
            state.advance()
            return True
        e.bchk_bp = op[2]
        state.advance()
        return True
    if kind == "bchk_idx_bp":
        if e.bchk_bp is None or op[2] != e.bchk_bp + 6:
            state.advance()
            return True
        m.si = m.ax
        m.ax = None
        e.bchk_bp = None
        state.advance()
        return True
    if kind == "bchk_span":  # Bounds 2-D: a range-checked non-final subscript
        # (the span-multiplied dim); stash it for shlsi to combine (F3.5).
        e.bchk_subs.append(m.ax)
        m.ax = None
        state.advance()
        return True
    return False
