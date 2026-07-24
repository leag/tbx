"""DOS/OS statement handlers: filesystem, SHELL, device I/O, sound, timing, date.

Handlers for ``decode_user_code``'s dispatch loop; each handler takes
the shared :class:`~tbx.decode0.core.DecodeState` plus the current
``op``/``addr``/``kind`` and returns ``True`` when it consumed the op.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from tbx import ir

if TYPE_CHECKING:
    from tbx.decode0.core import DecodeState


def filesystem(state: DecodeState, op, addr, kind) -> bool:
    """DOS filesystem statements: KILL / FILES / NAME / CHDIR / MKDIR / RMDIR.

    Each takes its path/spec string(s) off ``sstack`` and emits the statement.
    Returns True when handled (the loop should ``continue``).
    """
    if kind == "kill":  # KILL file$
        state.put(ir.Kill(state.sstack.pop()), state.cur)
    elif kind == "files":  # FILES spec$
        state.put(ir.Files(state.sstack.pop()), state.cur)
    elif kind == "files_bare":  # FILES
        state.put(ir.Files(), state.cur)
    elif kind == "name":  # NAME old$ AS new$ (new pushed first)
        new, old = state.sstack.pop(), state.sstack.pop()
        state.put(ir.Name(old, new), state.cur)
    elif kind == "chdir":  # CHDIR path$ (EC sub 10)
        state.put(ir.Chdir(state.sstack.pop()), state.cur)
    elif kind == "mkdir":  # MKDIR path$ (EC sub 6A)
        state.put(ir.Mkdir(state.sstack.pop()), state.cur)
    elif kind == "rmdir":  # RMDIR path$ (EC sub C2)
        state.put(ir.Rmdir(state.sstack.pop()), state.cur)
    else:
        return False
    state.cur = None
    state.k += 1
    return True


def os_system(state: DecodeState, op, addr, kind) -> bool:
    """Dispatch family: shell, chain, environ, reset, randomize, clear, bload, bsave."""
    if kind == "shell":  # SHELL cmd$ (EC sub CE)
        state.put(ir.Shell(state.sstack.pop()), state.cur)
        state.cur = None
        state.k += 1
        return True
    if kind == "chain":  # CHAIN file$ (EC sub 0E)
        state.put(ir.Chain(state.sstack.pop()), state.cur)
        state.cur = None
        state.k += 1
        return True
    if kind == "run_file":  # RUN file$ (EC sub C4)
        state.put(ir.Run(state.sstack.pop()), state.cur)
        state.cur = None
        state.k += 1
        return True
    if kind == "environ":  # ENVIRON s$ (EC sub 34)
        state.put(ir.Environ(state.sstack.pop()), state.cur)
        state.cur = None
        state.k += 1
        return True
    if kind == "reset":  # RESET: close all files
        state.put(ir.Reset(), state.cur)
        state.cur = None
        state.k += 1
        return True
    if kind == "randomize":  # RANDOMIZE seed (FP stack)
        state.put(ir.Randomize(state.stack.pop()), state.cur)
        state.cur = None
        state.k += 1
        return True
    if kind == "clear":  # CLEAR (zero operand)
        state.put(ir.Clear(), state.cur)
        state.cur = None
        state.k += 1
        return True
    if kind == "bload":  # BLOAD f$, offset
        offset = state.stack.pop()
        state.put(ir.Bload(state.sstack.pop(), offset), state.cur)
        state.cur = None
        state.k += 1
        return True
    if kind == "bload0":  # BLOAD f$: bare, no-offset form
        state.put(ir.Bload(state.sstack.pop()), state.cur)
        state.cur = None
        state.k += 1
        return True
    if kind == "bsave":  # BSAVE f$, offset, length
        length = state.stack.pop()
        offset = state.stack.pop()
        state.put(ir.Bsave(state.sstack.pop(), offset, length), state.cur)
        state.cur = None
        state.k += 1
        return True
    return False


def device_io(state: DecodeState, op, addr, kind) -> bool:
    """Dispatch family: out, out_imm, in_al, poke."""
    if kind == "out_imm":
        state.put(ir.Out(ir.Lit(op[2]), ir.Lit(op[3])), state.cur)
        state.cur = None
        state.k += 1
        return True
    if kind == "out":  # OUT port(dx), value(ax)
        state.put(ir.Out(state.dx, state.ax), state.cur)
        state.dx = state.ax = None
        state.cur = None
        state.k += 1
        return True
    if kind == "in_al":  # ax = INP(port in dx)
        state.ax = ir.Call("INP", (state.dx,))
        state.dx = None
        state.k += 1
        return True
    if kind == "poke":  # POKE addr(FP), value(ax)
        state.put(ir.Poke(state.stack.pop(), state.ax), state.cur)
        state.ax = None
        state.cur = None
        state.k += 1
        return True
    return False


def devwait(state: DecodeState, op, addr, kind) -> bool:
    """Dispatch family: wait_poll, wait_poll3."""
    if kind == "wait_poll":  # WAIT port(dx), mask(bx)
        state.put(ir.Wait(state.dx, state.bx), state.cur)
        state.dx = state.bx = None
        state.cur = None
        state.k += 1
        return True
    if kind == "wait_poll3":  # WAIT port(dx), and(cx), xor(bx)
        state.put(ir.Wait(state.dx, state.cx, state.bx), state.cur)
        state.dx = state.bx = state.cx = None
        state.cur = None
        state.k += 1
        return True
    return False


def sound(state: DecodeState, op, addr, kind) -> bool:
    """Dispatch family: beep, sound, play."""
    if kind == "beep":  # BEEP (zero operand)
        state.put(ir.Beep(), state.cur)
        state.cur = None
        state.k += 1
        return True
    if kind == "sound":  # SOUND freq(ax), dur(FP stack)
        dur = state.stack.pop()
        if state.ax is None or isinstance(state.ax, tuple):
            raise ValueError(f"SOUND without a freq argument at {addr:#x}")
        state.put(ir.Sound(state.ax, dur), state.cur)
        state.ax = None
        state.cur = None
        state.k += 1
        return True
    if kind == "play":  # PLAY music$
        state.put(ir.Play(state.sstack.pop()), state.cur)
        state.cur = None
        state.k += 1
        return True
    return False


def timing(state: DecodeState, op, addr, kind) -> bool:
    """Dispatch family: delay_init, mtimer."""
    if kind == "delay_init":  # DELAY secs (FP) + poll loop tail
        secs = state.stack.pop()
        # Under active event trapping, a per-statement CC poll hook (q.v.
        # trap_hook's own generic handler) can land between delay_init and
        # delay_poll -- skip it here too (recording its addr into cc_hooks,
        # mirroring the generic path) rather than treating it as a template
        # break (wild prtguide.exe/readme.exe, both under ON TIMER/KEY
        # event trapping). A hook immediately BEFORE delay_poll also
        # re-stamps the loop's own back-jump onto the HOOK's address, not
        # delay_poll's (the same trace-hook quirk `_has_jmps_back` already
        # documents for WHILE loops): track that as the effective target.
        j = state.k + 1
        loop_back = None
        while j < len(state.ops) and state.ops[j][1] == "trap_hook":
            state.cc_hooks.add(state.ops[j][0])
            if loop_back is None:
                loop_back = state.ops[j][0]
            j += 1
        if j >= len(state.ops) or state.ops[j][1] != "delay_poll":
            raise ValueError(f"DELAY without poll op at {addr:#x}")
        if loop_back is None:
            loop_back = state.ops[j][0]
        j += 1
        if j >= len(state.ops):
            raise ValueError(f"DELAY without poll back-jump at {addr:#x}")
        jc = state.ops[j]
        if jc[1] != "jcc" or jc[3] != loop_back:
            raise ValueError(f"DELAY without poll back-jump at {addr:#x}")
        state.put(ir.Delay(secs), state.cur)
        state.cur = None
        state.k = j + 1  # consume delay_init, any hooks, delay_poll, jcc
        return True
    if kind == "mtimer":  # MTIMER (zero operand)
        state.put(ir.Mtimer(), state.cur)
        state.cur = None
        state.k += 1
        return True
    return False


def datetime(state: DecodeState, op, addr, kind) -> bool:
    """Dispatch family: dateset, timeset."""
    if kind in ("dateset", "timeset"):  # DATE$/TIME$ = s$
        state.put(
            ir.DateTimeSet(
                "DATE$" if kind == "dateset" else "TIME$", state.sstack.pop()
            ),
            state.cur,
        )
        state.cur = None
        state.k += 1
        return True
    return False


def segments(state: DecodeState, op, addr, kind) -> bool:
    """Dispatch family: defseg, defseg_set."""
    if kind == "defseg":  # bare DEF SEG: restore DS
        state.put(ir.DefSeg(None), state.cur)
        state.cur = None
        state.k += 1
        return True
    if kind == "defseg_set":  # DEF SEG = <fp>
        state.put(ir.DefSeg(state.stack.pop()), state.cur)
        state.cur = None
        state.k += 1
        return True
    return False


def bounds(state: DecodeState, op, addr, kind) -> bool:
    """Dispatch family: bchk0, bchk_span, bchk_base_bp, bchk_idx_bp."""
    if kind == "bchk0":  # Bounds: xor si,si starts a checked index; reset the
        state.bchk_subs = []  # pending non-final subscripts (F3.4/F3.5)
        state.bchk_bp = None
        state.k += 1
        return True
    if kind == "bchk_base_bp":
        if (
            (state.proc_frame is None and state.fn_frame is None)
            or op[2] not in state.r_arrs
            or state.r_arrs[op[2]]["rank"] != 1
        ):
            raise ValueError(f"LOCAL bounds base mismatch at {addr:#x}")
        state.bchk_bp = op[2]
        state.k += 1
        return True
    if kind == "bchk_idx_bp":
        if state.bchk_bp is None or op[2] != state.bchk_bp + 6:
            raise ValueError(f"LOCAL bounds index mismatch at {addr:#x}")
        state.si = state.ax
        state.ax = None
        state.bchk_bp = None
        state.k += 1
        return True
    if kind == "bchk_span":  # Bounds 2-D: a range-checked non-final subscript
        # (the span-multiplied dim); stash it for shlsi to combine (F3.5).
        state.bchk_subs.append(state.ax)
        state.ax = None
        state.k += 1
        return True
    return False
