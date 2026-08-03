"""Control-flow handlers: CALL, runtime dispatch, ON, error trap, strings, movax.

Handlers for ``decode_user_code``'s dispatch loop; each handler takes
the shared :class:`~tbx.decode0.core.DecodeState` plus the current
``op``/``addr``/``kind`` and returns ``True`` when it consumed the op.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from tbx import ir
from tbx.decode0.frames import BoolTerm, PrintChain, UsingChain
from tbx.decode0.const import (
    _JCC_RELOP_STR_TRUE,
    _JCC_RELOP_TRUE,
    _JCC_RELOP_VALUE,
    _TRAP_CTL,
    _TRAP_GOSUB,
    _pp_commas,
)
from tbx.decode0.lift import (
    _lift_bool_do_tail,
    _lift_bool_tail,
    _lift_do_tail,
    _lift_while,
)
from tbx.decode0.matchers import (
    match_second_using_before_flush,
    array_param_suffix,
    match_bool_outer_and_group,
    match_bool_term1,
    match_numeric_logical_value_group,
    match_string_logical_value_group,
    match_using_emit,
)

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from tbx.decode0.core import DecodeState


def _forwarded_arg(state: DecodeState, op, addr, index, argument):
    c = state.control
    params = c.proc_params.get(op[2])
    if params is None:
        return ("fwdpending", op[2], index, argument[1])
    if op[2] in c.inline_procs:
        offset = argument[1]
        c.fwd_inline_offs.add(offset)
        return ir.Var(f"P{offset:02X}")
    if index >= len(params):
        raise ValueError(
            f"forwarded arg index {index} to callee {op[2]:#x} "
            f"with {len(params)} params at {addr:#x}"
        )
    suffix = params[index][-1] if params[index][-1] in "%$" else ""
    offset = argument[1]
    if suffix == "%":
        c.proc_int_offs.add(offset)
    elif suffix == "$":
        c.proc_str_offs.add(offset)
    return ir.Var(f"P{offset:02X}{suffix}")


def _byref_arg(state: DecodeState, op, addr, index, argument):
    l, c = state.layout_state, state.control
    params = c.proc_params.get(op[2])
    offset = argument[1]
    if params is None:
        try:
            fallback = state.loc(offset)
        except ValueError:
            fallback = ir.Var(f"V{offset:04X}")
        return ("argrefpending", op[2], index, offset, fallback)
    if op[2] in c.inline_procs:
        return state.loc(offset)
    if index >= len(params):
        raise ValueError(f"by-ref arg to unknown callee params at {addr:#x}")
    suffix = params[index][-1] if params[index][-1] in "%$&#" else ""
    if suffix == "%":
        l.lay["scalars"][offset] = 2
    elif suffix == "&":
        l.lay["scalars"][offset] = 4
        l.lay["long_slots"].add(offset)
    elif suffix == "#":
        l.lay["scalars"][offset] = 8
    elif suffix == "$":
        l.lay["strs"].add(offset)
    else:
        l.lay["scalars"][offset] = 4
    return state.loc(offset)


def _far_call(state: DecodeState, op, addr) -> bool:
    c = state.control
    args = tuple(
        _forwarded_arg(state, op, addr, index, argument)
        if isinstance(argument, tuple) and argument[0] == "fwd"
        else _byref_arg(state, op, addr, index, argument)
        if isinstance(argument, tuple) and argument[0] == "argref"
        else argument
        for index, argument in enumerate(c.pend_args)
    )
    c.pend_args.clear()
    name = c.proc_names.get(op[2], ("addr", op[2]))
    state.put(ir.CallStmt(name, args), c.cur if c.cur is not None else addr)
    c.cur = None
    state.advance()
    return True


def _fn_call(state: DecodeState, op) -> bool:
    img, e, c = state.image, state.expr, state.control
    args = tuple(c.fn_args[offset] for offset in sorted(c.fn_args))
    c.fn_args.clear()
    name = c.proc_names.get(op[2], ("addr", op[2]))
    call = ir.FnCall(name, args)
    nxt = img.ops[c.k + 1] if c.k + 1 < len(img.ops) else None
    if nxt is not None and nxt[1] == "fnres_spush":
        e.sstack.append(call)
        state.advance(2)
    else:
        e.stack.append(call)
        state.advance()
    return True


def calls(state: DecodeState, op, addr, kind) -> bool:
    """Dispatch family: call_abs, call_int, far_call, fn_call."""
    m, e, c = state.machine, state.expr, state.control
    if kind == "call_abs":  # CALL ABSOLUTE addr
        state.put(ir.CallAbsolute(e.stack.pop()), c.cur)
        c.cur = None
        state.advance()
        return True
    if kind == "call_int":  # CALL INTERRUPT n
        state.put(ir.CallInterrupt(m.ax), c.cur)
        m.ax = None
        c.cur = None
        state.advance()
        return True
    if kind == "far_call":
        return _far_call(state, op, addr)
    if kind == "fn_call":  # drain staged args (offset order) -> FnCall
        return _fn_call(state, op)
    return False


def _arg_ref(state: DecodeState, op, addr) -> bool:
    c = state.control
    if c.cur is None:
        c.cur = addr
    c.pend_arg = op[2]
    state.advance()
    return True


def _arg_push_ref(state: DecodeState, op, addr) -> bool:
    l, c = state.layout_state, state.control
    if c.cur is None:
        c.cur = addr
    try:
        if op[2] in l.lay.get("guessed", ()):
            raise ValueError("by-ref slot width was guessed, not evidenced")
        c.pend_args.append(state.loc(op[2]))
    except ValueError:
        c.pend_args.append(("argref", op[2]))
    state.advance()
    return True


def _arg_push_array_bp(state: DecodeState, op, addr) -> bool:
    i, c = state.image, state.control
    if c.proc_frame is None:
        raise ValueError(f"whole-array parameter push outside a SUB at {addr:#x}")
    if c.cur is None:
        c.cur = addr
    record = c.proc_frame.array_params.setdefault(op[2], {"rank": 1})
    record.setdefault("name", f"P{op[2]:02X}" + array_param_suffix(i.ops, c.k, op[2]))
    c.pend_args.append(ir.ArrayRef(record["name"], ()))
    state.advance()
    return True


def _arg_push_ref_bp(state: DecodeState, op) -> bool:
    i, c = state.image, state.control
    is_fn_string_param = (
        c.fn_frame is not None
        and not (
            c.fn_frame.locals is not None and op[2] in c.fn_frame.locals
        )
        and any(
            candidate[1] == "arg_ref"
            and candidate[2] == op[2]
            and c.k + 1 + offset + 1 < len(i.ops)
            and i.ops[c.k + 1 + offset + 1][1] == "str_temp_free"
            for offset, candidate in enumerate(i.ops[c.k + 1 :])
        )
    )
    if is_fn_string_param:
        c.fn_frame.param_offs.add(op[2])
        c.fn_frame.str_offs.add(op[2])
        c.pend_args.append(ir.Var(f"P{op[2]:02X}$"))
    else:
        c.pend_args.append(state.loc_local(op[2]))
    state.advance()
    return True


def _arg_push_fwd(state: DecodeState, op) -> bool:
    state.control.pend_args.append(("fwd", op[2]))
    state.advance()
    return True


def _restore_array_ds(state: DecodeState, op) -> bool:
    i, c = state.image, state.control
    if (
        op[1] == "movdx"
        and c.k + 1 < len(i.ops)
        and i.ops[c.k + 1][1] == "movdsdx"
        and c.k
        and i.ops[c.k - 1][1] == "arg_push_array_bp"
    ):
        state.advance(2)
        return True
    return False


def cargs(state: DecodeState, op, addr, kind) -> bool:
    """Dispatch family: arg_ref, arg_push_ref."""
    if kind == "arg_ref":
        return _arg_ref(state, op, addr)
    if kind == "arg_push_ref":
        return _arg_push_ref(state, op, addr)
    if kind == "arg_push_array_bp":
        return _arg_push_array_bp(state, op, addr)
    if kind == "movdx" and _restore_array_ds(state, op):
        return True
    if kind == "arg_push_ref_bp":
        return _arg_push_ref_bp(state, op)
    if kind == "arg_push_fwd":
        return _arg_push_fwd(state, op)
    return False


def _runtime_using_emit(state: DecodeState, addr: int) -> bool:
    i, e, c = state.image, state.expr, state.control
    emit = match_using_emit(i.ops, c.k)
    if e.pend_using is None or emit is None:
        raise ValueError(f"stray USING emit at {addr:#x}")
    lp = emit.leg == "printer"
    f = e.pend_fnum if emit.leg == "file" else None
    if emit.leg == "file" and f is None:
        raise ValueError(f"file USING item without [0060] at {addr:#x}")
    if e.pend_using.values and (
        e.pend_using.file != f or e.pend_using.lprint != lp
    ):
        raise ValueError(f"USING console/file leg flip at {addr:#x}")
    e.pend_using.file = f
    e.pend_using.lprint = lp
    e.pend_using.values.append(
        e.stack.pop() if emit.numeric else e.sstack.pop()
    )
    c.cur = None
    state.advance(2)
    return True


def _runtime_print_item(state: DecodeState, addr: int, vec: int) -> bool:
    e, c = state.expr, state.control
    if e.pend_using is not None:
        if not state.close_nested_using():  # ...into its owner, if nested
            state.flush_pending()
    f = e.pend_fnum if vec in (0xBD, 0xC0) else None
    if vec in (0xBD, 0xC0) and f is None:
        raise ValueError(f"file print item without [0060] at {addr:#x}")
    if e.pend_print is not None and e.pend_print.file != f:
        state.flush_pending()  # console/file leg change = new stmt
    if e.pend_print is None:
        e.pend_print = PrintChain(file=f, start=c.cur)
    e.pend_print.items.append(
        e.sstack.pop() if vec in (0xBE, 0xC0) else e.stack.pop()
    )
    c.cur = None
    state.advance()
    return True


def runtime_call(state: DecodeState, op, addr, kind) -> bool:
    """Dispatch family: rt."""
    i, e, c = state.image, state.expr, state.control
    if kind == "rt":  # PRINT chains
        vec = op[2]
        logger.debug("runtime vector %02x at %05x; pending_print=%s", vec, addr, e.pend_print is not None)
        if vec == 0x9C and c.k > 0 and i.ops[c.k - 1][1] == "movsi":
            # String descriptor push reached the generic runtime dispatcher
            # after a checked-call helper in a large wild program.
            d = i.ops[c.k - 1][2]
            is_local = d in state.layout_state.lay["strs"] or any(
                a["str"] and a["base"] <= d < a["base"] + a["esz"] * a["count"]
                for a in state.layout_state.arrs
            )
            e.sstack.append(state.loc(d) if is_local else state._pool_str(d))
            state.advance()
            return True
        if vec == 0xCA:  # USING begin: fmt off the sstack
            # More than one USING can live in ONE print statement, and that
            # form has no byte-equal split spelling (t1_usingtwice), so the
            # USING has to become an ITEM of the open chain rather than end it.
            # Two conditions, both necessary:
            #   - another `rt CA` before this statement's flush, and
            #   - NO per-statement commit marker in the span between them.
            # The marker is what separates wild banker.exe (none in the span,
            # one statement) from wild inv87.exe / invoice.exe (a marker before
            # the second clause, so genuinely two). Checking the span is the
            # point: an earlier attempt tested from the CHAIN's start instead
            # and merged statements that were never one, ledger
            # RO-COMMIT-MARKER-BOUNDARY.
            outer = e.pend_print
            multi = False
            if outer is not None:
                if any(isinstance(x, ir.PrintUsing) for x in outer.items):
                    multi = True  # already inside a multi-USING statement
                else:
                    second = match_second_using_before_flush(i.ops, c.k)
                    multi = second is not None and not (
                        state.statement_boundary_between(
                            addr, i.ops[second.start][0]
                        )
                    )
            if not multi:
                state.flush_pending()
                outer = None
            e.pend_using = UsingChain(
                fmt=e.sstack.pop(), start=c.cur, nested_in=outer
            )
            c.cur = None
            state.advance()
            return True
        if vec in (0xCB, 0xCC):  # USING emit + its string item vec: CB formats a
            # numeric off the FP stack, CC a string off the sstack (t1_using);
            # item vec BE = console, C0 = file, BF = printer (LPRINT USING,
            # witnessed t1_lpusing / wild vhfprop.exe)
            return _runtime_using_emit(state, addr)
        if vec in (0xC1, 0xC2, 0xC3):  # PRINT comma: zone-advance separator
            # (C1 console / C2 printer / C3 file, witnessed t1_pcomma,
            # wild billadd/prtguide/rs, and t1_fileint); commas may
            # LEAD the items (`PRINT ,,X`) and repeat (`PRINT A,,B` skips a
            # zone) -- witnessed t1_pcomma2 / wild schart.exe (console) and
            # q_fpcomma / wild styllist.exe (`PRINT #n, , X`, file channel)
            want_file = vec == 0xC3
            want_lprint = vec == 0xC2
            if e.pend_print is None and not want_file:
                e.pend_print = PrintChain(
                    items= [],
                    file= None,
                    start= c.cur,
                    mode="lprint" if want_lprint else None,
                )
            elif e.pend_print is None and want_file:
                e.pend_print = PrintChain(
                    items= [],
                    file= e.pend_fnum,
                    start= c.cur,
                )
            if (
                e.pend_print is None
                or e.pend_print.mode != (
                    "lprint" if want_lprint else None
                )
                or (e.pend_print.file is not None) != want_file
            ):
                raise ValueError(f"comma separator without print item at {addr:#x}")
            cs = e.pend_print.commas
            gap = len(e.pend_print.items)
            cs[gap] = cs.get(gap, 0) + 1
            c.cur = None
            state.advance()
            return True
        if vec in (0xBB, 0xBE, 0xBD, 0xC0):  # item-eval vectors
            return _runtime_print_item(state, addr, vec)
        if vec in (0xBC, 0xBF):  # LPRINT item-eval (printer): BC numeric off the
            # FP stack, BF string off the sstack (witnessed t1_lpstr)
            item = e.sstack.pop() if vec == 0xBF else e.stack.pop()
            if e.pend_using is not None:  # plain item closes a USING chain
                if not state.close_nested_using():  # ...into its owner, if nested
                    state.flush_pending()
            if (
                e.pend_print is not None
                and e.pend_print.mode != "lprint"
            ):
                state.flush_pending()
            if e.pend_print is None:
                e.pend_print = PrintChain(
                    items= [],
                    file= None,
                    start= c.cur,
                    mode= "lprint",
                )
            e.pend_print.items.append(item)
            c.cur = None
            state.advance()
            return True
        if vec == 0xB9:  # LPRINT flush-newline
            state.close_nested_using()  # an item of the chain, not a statement
            if e.pend_using is not None:  # LPRINT USING closes on B9 too
                pu, e.pend_using = e.pend_using, None
                if not pu.lprint:
                    raise ValueError(f"b9 flush of a non-printer USING at {addr:#x}")
                state.put(
                    ir.PrintUsing(
                        pu.fmt,
                        tuple(pu.values),
                        newline=True,
                        lprint=True,
                    ),
                    pu.start,
                )
                c.cur = None
                state.advance()
                return True
            if e.pend_print is None:  # bare LPRINT: blank line (t1_lpstr)
                state.put(ir.Lprint(()), c.cur)
                c.cur = None
                state.advance()
                return True
            if e.pend_print.mode != "lprint":
                logger.warning(
                    "B9 flush closes non-printer print chain (%s) at %x",
                    e.pend_print.mode,
                    addr,
                )
                pp, e.pend_print = e.pend_print, None
                state.put(ir.Lprint(tuple(pp.items), commas=_pp_commas(pp)), pp.start)
                c.cur = None
                state.advance()
                return True
            pp, e.pend_print = e.pend_print, None
            state.put(
                ir.Lprint(tuple(pp.items), commas=_pp_commas(pp)),
                pp.start,
            )
            c.cur = None
            state.advance()
            return True
        if vec in (0xB8, 0xBA):  # flush-newline: statement complete
            want_file = vec == 0xBA
            state.close_nested_using()  # an item of the chain, see the B9 leg
            if e.pend_using is not None:
                pu, e.pend_using = e.pend_using, None
                if (pu.file is not None) != want_file:
                    raise ValueError(f"USING flush leg mismatch at {addr:#x}")
                state.put(
                    ir.PrintUsing(
                        pu.fmt,
                        tuple(pu.values),
                        file=pu.file,
                        newline=True,
                    ),
                    pu.start,
                )
            elif e.pend_print is not None:
                pp, e.pend_print = e.pend_print, None
                if (pp.file is not None) != want_file:
                    raise ValueError(f"print flush leg mismatch at {addr:#x}")
                if pp.mode == "write":
                    state.put(
                        ir.Write(tuple(pp.items), file=pp.file), pp.start
                    )
                else:
                    state.put(
                        ir.Print(
                            tuple(pp.items),
                            file=pp.file,
                            commas=_pp_commas(pp),
                        ),
                        pp.start,
                    )
            elif not want_file:
                state.put(ir.Print(()), c.cur)  # bare PRINT (blank line)
            else:
                # bare `PRINT #n,` (wild be.exe/styllist.exe, probe
                # q_fprintblank): a blank-line flush to a file channel, no
                # staged pend_print at all since there were no items.
                state.put(ir.Print((), file=e.pend_fnum), c.cur)
            if want_file:
                e.pend_fnum = None
            c.cur = None
            state.advance()
            return True
        raise ValueError(f"unhandled runtime INT {vec:02x} at {addr:#x}")
    return False


def on_control(state: DecodeState, op, addr, kind) -> bool:
    """Dispatch family: on_goto, on_gosub."""
    m, c = state.machine, state.control
    if kind in ("on_goto", "on_gosub"):  # ON <sel> GOTO/GOSUB (EC sub 74/72)
        if m.ax is None:
            raise ValueError(f"ON without selector in ax at {addr:#x}")
        targets = tuple(("addr", t) for t in op[2:])
        cls = ir.OnGoto if kind == "on_goto" else ir.OnGosub
        state.put(cls(m.ax, targets), c.cur)
        m.ax = None
        c.cur = None
        state.advance()
        return True
    return False


def _finish_control_statement(state: DecodeState, statement, steps=1) -> bool:
    c = state.control
    state.put(statement, c.cur)
    c.cur = None
    state.advance(steps)
    return True


def _on_error(state: DecodeState, op) -> bool:
    target = None if op[2] is None else ("addr", op[2])
    return _finish_control_statement(state, ir.OnError(target))


def _on_trap(state: DecodeState, op) -> bool:
    m, e = state.machine, state.expr
    event = _TRAP_GOSUB[op[2]]
    if event == "TIMER":
        number = e.stack.pop()
    elif event == "PEN":
        number = None
    else:
        number, m.ax = m.ax, None
    return _finish_control_statement(
        state, ir.OnTrap(event, number, ("addr", op[3]))
    )


def _error_statement(state: DecodeState) -> bool:
    m = state.machine
    statement = ir.ErrorStmt(m.ax)
    m.ax = None
    return _finish_control_statement(state, statement)


def _resume_statement(state: DecodeState, addr) -> bool:
    i, c = state.image, state.control
    nxt = i.ops[c.k + 1] if c.k + 1 < len(i.ops) else None
    if nxt is not None and nxt[1] == "resume_bare":
        statement = ir.Resume()
    elif nxt is not None and nxt[1] == "resume_next":
        statement = ir.Resume(next_=True)
    elif nxt is not None and nxt[1] in ("jmps", "jmp", "jmpf"):
        statement = ir.Resume(target=("addr", nxt[2]))
    elif nxt is not None and nxt[1] == "run":
        statement = ir.Resume(target=("addr", i.start + 3))
    else:
        raise ValueError(f"RESUME tail {nxt} at {addr:#x} (unsupported)")
    return _finish_control_statement(state, statement, steps=2)


def _trap_control(state: DecodeState, op) -> bool:
    m = state.machine
    event, mode = _TRAP_CTL[op[2]]
    number = None
    if event in ("COM", "KEY"):
        number, m.ax = m.ax, None
    return _finish_control_statement(state, ir.TrapCtl(event, number, mode))


def _trap_hook(state: DecodeState) -> bool:
    state.output.cc_hooks.add(state.control.cur)
    state.advance()
    return True


def errors_trap(state: DecodeState, op, addr, kind) -> bool:
    """Dispatch family: error, resume, and event-trap statements."""
    handlers = {
        "on_error": lambda: _on_error(state, op),
        "on_trap": lambda: _on_trap(state, op),
        "error_stmt": lambda: _error_statement(state),
        "resume_pre": lambda: _resume_statement(state, addr),
        "trap_ctl": lambda: _trap_control(state, op),
        "trap_hook": lambda: _trap_hook(state),
    }
    handler = handlers.get(kind)
    return handler() if handler is not None else False


def string_ops(state: DecodeState, op, addr, kind) -> bool:
    """Dispatch family: strconcat, str_store_temp."""
    e, c, m, i = state.expr, state.control, state.machine, state.image
    if kind == "strconcat":  # pops two strings, pushes concat
        rhs = e.sstack.pop()
        lhs = e.sstack.pop()
        e.sstack.append(ir.BinOp("+", lhs, rhs))
        state.advance()
        return True
    if kind == "str_store_temp":  # CD A3: materialized string literal CALL arg
        # Staging an argument, NOT ending a statement: keep `c.cur`. Clearing
        # it discarded the address the statement had already taken -- under
        # event trapping that is the poll stamp the whole run starts at, so a
        # branch to the CALL then matched no statement (wild rsltest.exe,
        # `jump target 0xf325`; the address reappeared at the `push_bp` two ops
        # later, 0xf352, which nothing names). Every sibling staging op --
        # `arg_push_temp`, `movm_ax_temp`, `mov_mem_sp` -- leaves it alone.
        value = e.sstack.pop()
        nxt = i.ops[c.k + 1] if c.k + 1 < len(i.ops) else None
        if nxt is not None and nxt[1] == "arg_push_temp":
            # Ordinary SUB CALL argument: the explicit push marker drains the
            # ordered pending list at far_call (probe t1_dynprint).  A direct
            # variable reached this path through `movsi; rt 9C`, which is the
            # compiler's encoding of a parenthesized string argument; retain
            # that grouping or the emitter changes the descriptor push into a
            # by-reference argument (wild CVT2TB's CALL SUB1).
            if isinstance(value, ir.Var):
                value = ir.Group(value)
            c.pend_args.append(value)
        else:
            # A string argument to a nested DEF FN has no arg_push_temp.  Its
            # temp slot is keyed by SI just like movm_ax_temp/fstp_temp; keep
            # it in the FN argument map or it leaks into the next SUB CALL's
            # pending list (wild CVT2TB, FNFN2$ inside the call at 0xc9c6).
            if m.si is None:
                raise ValueError(f"string temp without SI at {addr:#x}")
            c.fn_args[m.si] = value
        state.advance()
        return True
    return False


def movax_family(state: DecodeState, op, addr, kind) -> bool:
    """Ordered multi-branch dispatch family: movax."""
    i, m, e, c, o = (state.image, state.machine, state.expr,
                     state.control, state.output)
    if kind == "movax" and op[2] == 0xFFFF and e.pend_icmp is not None:
        # Relational-as-value: `cmp ax,[mem]; mov ax,FFFF; jcc cc; inc ax`.
        if (
            c.k + 2 >= len(i.ops)
            or i.ops[c.k + 1][1] != "jcc"
            or i.ops[c.k + 2][1] != "incax"
        ):
            raise ValueError(f"relational-value: expected jcc+incax at {addr:#x}")
        if (
            c.k + 3 < len(i.ops)
            and i.ops[c.k + 3][1] in ("orax", "andaxbx")
        ):
            # Integer compare feeding the compound-IF/WHILE materialization
            # template (`IF ERR = 25 OR ERR = 27 ...`, witnessed t1_orchain /
            # wild vhfprop.exe): hand the compare to the pend_cmp machinery
            # below. Preserve cmpax_m's stored source orientation: reversing
            # the operands is logically equivalent but recompiles to different
            # bytes. Wild number.exe/pfl.exe and t1_orrel exercise JG/JL.
            cc = i.ops[c.k + 1][2]
            if cc not in _JCC_RELOP_VALUE:
                raise ValueError(f"int compound relational jcc {cc:02x} at {addr:#x}")
            if cc in (0x7C, 0x7D, 0x7E, 0x7F):
                # The generic compound lifter reads _JCC_RELOP_TRUE, while
                # cmpax_m's materialized-value shape uses the inverse signed
                # relation table. Normalize only the condition code consumed by
                # the lifter; the jump target and scanned golden op stay raw.
                mapped = {0x7C: 0x7F, 0x7D: 0x7E, 0x7E: 0x7D, 0x7F: 0x7C}[cc]
                jcc = i.ops[c.k + 1]
                i.ops[c.k + 1] = (jcc[0], jcc[1], mapped, *jcc[3:])
            e.pend_cmp = e.pend_icmp
            e.pend_icmp = None
        else:
            relop = _JCC_RELOP_VALUE.get(i.ops[c.k + 1][2])
            if relop is None:
                raise ValueError(f"relational-value: unmapped jcc at {addr:#x}")
            lhs, rhs = e.pend_icmp
            e.pend_icmp = None
            m.ax = ir.BinOp(relop, lhs, rhs)
            state.advance(3)  # consume movax FFFF, jcc, incax
            return True
    if kind == "movax" and e.pend_cmp and op[2] == 0xFFFF:
        frame = c.proc_frame if c.proc_frame is not None else c.fn_frame
        scope_start = state.frame_start(frame.seq) if frame is not None else 0
        if e.pend_bool is not None:  # compound-IF tail
            nk = _lift_bool_do_tail(
                i.ops,
                c.k,
                e.pend_cmp,
                e.pend_bool,
                o.stmts,
                o.addrs,
                state.put,
                shift=state.shift_pending,
                scope_start=scope_start,
            )  # compound DO..LOOP WHILE/UNTIL?
            if nk is not None:
                state.seek(nk)
                e.pend_bool = None
            else:
                c.k, e.pend_bool, e.pend_bool_outer = _lift_bool_tail(
                    i.ops,
                    c.k,
                    e.pend_cmp,
                    e.pend_bool,
                    state.put,
                    c.whiles,
                    c.ifs,
                    o.stmts,
                    state.flush_pending,
                    e.pend_bool_outer,
                    branch=state.branch,
                )  # a mid-chain segment keeps pend_bool open (t1_and3)
            e.pend_cmp = None
            e.pend_cmp_str = False
            c.cur = None
            return True
        # Use the legacy index as the source of truth while this handler still
        # shares the dispatch loop with non-cursor handlers.  The matcher is
        # pure, so this keeps recognition independent from cursor history.
        if (
            e.pend_cmp_str
            and match_string_logical_value_group(i.ops, c.k) is not None
        ):
            lhs, rhs = e.pend_cmp
            m.ax = ir.BinOp(
                _JCC_RELOP_STR_TRUE[i.ops[c.k + 1][2]], lhs, rhs
            )
            e.pend_cmp = None
            e.pend_cmp_str = False
            e.direct_bool_gate = True
            e.direct_bool_group = "string_value"
            e.direct_bool_logical = True
            state.advance(3)
            return True
        if (
            e.pend_cmp
            and not e.pend_cmp_str
            and match_numeric_logical_value_group(i.ops, c.k) is not None
        ):
            # Mirror of the string-led value group just above, numeric first
            # and a string relation second (wild kinder.exe): the shared tail
            # (strcmp; movbxax; movax FFFF; jcc; incax; oraxbx; ...) folds
            # the same way regardless of which side led, EXCEPT the operand
            # order: string-led banks term1(string) to bx then materializes
            # term2(numeric) into ax, so its fold puts ax(term2) first --
            # numeric-led is the mirror image (bx=term1 numeric, ax=term2
            # string), so ITS fold must put bx(term1) first instead, or a
            # 3+-term chain nests the wrong operand order once this fold's
            # result itself becomes an operand of the next one (checked:
            # sharing "string_value" here reproduced byte-exact for an
            # isolated 2-term probe -- OR being commutative hid it -- but
            # broke a 3-term chain's inner nesting, probe q_numstr3chain).
            e.direct_bool_group = "numeric_value"
            lhs, rhs = e.pend_cmp
            m.ax = ir.BinOp(_JCC_RELOP_TRUE[i.ops[c.k + 1][2]], lhs, rhs)
            e.pend_cmp = None
            e.direct_bool_gate = True
            e.direct_bool_logical = True
            state.advance(3)
            return True
        if match_bool_outer_and_group(i.ops, c.k) is not None:
            # The materialized left term of `A AND (B OR C)` is preserved
            # through BX/CX while the right group uses its own spill fold.
            # Check this before the generic mixed-precedence matcher: numeric
            # groups also expose a later final AND, which otherwise looks like
            # a deferred flat chain. The protocol is shared by string terms
            # (t1_boolstrgroup) and integer relations
            # (v10_t1_intandorgroup; wild file.exe).
            m.ax = ir.RelOp(_JCC_RELOP_TRUE[i.ops[c.k + 1][2]], *e.pend_cmp)
            e.pend_cmp = None
            e.pend_cmp_str = False
            e.direct_bool_gate = True
            e.direct_bool_group = (
                "numeric_right"
                if not any(o[1] == "strcmp" for o in i.ops[c.k + 6 : c.k + 36])
                else None
            )
            e.direct_bool_logical = True
            state.advance(6)
            return True
        comb = match_bool_term1(i.ops, c.k)  # compound-IF first term?
        if comb is not None:
            op, deferred = comb.operator, comb.deferred
            r1 = ir.RelOp(_JCC_RELOP_TRUE[i.ops[c.k + 1][2]], *e.pend_cmp)
            if deferred:
                # `A OR B AND C`-shaped (wild wb.exe/grdscn.exe/mcmurphy.exe):
                # B and C form their OWN group first; hold this term as the
                # enclosing accumulator and let the ordinary dispatch loop
                # re-enter match_bool_term1 fresh at ops[k+6]. If an outer
                # accumulator is already waiting (a left-associative cascade
                # of GROUPS, `(A AND B) OR C AND D OR ...`, wild
                # mcmurphy.exe, probe q_mixedbool7), fold it in now rather
                # than stacking a second level.
                if e.pend_bool_outer is not None:
                    r1 = ir.LogOp(e.pend_bool_outer.op, e.pend_bool_outer.r1, r1)
                    start = e.pend_bool_outer.start
                else:
                    start = c.cur
                e.pend_bool_outer = BoolTerm(r1=r1, op=op, start=start)
            else:
                e.pend_bool = BoolTerm(
                    r1=r1,
                    op=op,
                    sc=i.ops[c.k + 5][2],
                    start=c.cur,
                )
            e.pend_cmp = None
            e.pend_cmp_str = False
            state.advance(6)
            return True
        nk = _lift_do_tail(
            i.ops,
            c.k,
            e.pend_cmp,
            o.stmts,
            o.addrs,
            state.put,
            c.cur,
            shift=state.shift_pending,
            scope_start=scope_start,
        )  # DO..LOOP WHILE/UNTIL
        if nk is not None:
            state.seek(nk)
            e.pend_cmp = None
            e.pend_cmp_str = False
            c.cur = None
            return True
        _group_term_map = (
            _JCC_RELOP_STR_TRUE if e.pend_cmp_str else _JCC_RELOP_TRUE
        )
        if (
            e.direct_bool_gate
            and m.bx is not None
            and c.k + 3 < len(i.ops)
            and i.ops[c.k + 1][1] == "jcc"
            and i.ops[c.k + 2][1] == "incax"
            and i.ops[c.k + 3][1] == "andaxbx"
            and i.ops[c.k + 1][3] == i.ops[c.k + 3][0]
            and i.ops[c.k + 1][2] in _group_term_map
        ):
            # The right side of `((a) OR (b)) AND (c)` is a single
            # parenthesized relation. It materializes directly into AX and is
            # immediately combined with the short-circuited left side in BX,
            # rather than using the normal six-op IF/loop tail template.
            # String relations use strcmp's forward flag map
            # (t1_nestedmixedstr; wild kinetics.exe).
            lhs, rhs = e.pend_cmp
            m.ax = ir.Group(
                ir.BinOp(_group_term_map[i.ops[c.k + 1][2]], lhs, rhs)
            )
            e.pend_cmp = None
            e.pend_cmp_str = False
            state.advance(3)
            return True
        if (
            not e.direct_bool_gate
            and m.bx is not None
            and not e.pend_cmp_str
            and c.k + 3 < len(i.ops)
            and i.ops[c.k + 1][1] == "jcc"
            and i.ops[c.k + 2][1] == "incax"
            and i.ops[c.k + 3][1] in ("andaxbx", "oraxbx")
            and i.ops[c.k + 1][3] == i.ops[c.k + 3][0]
            and i.ops[c.k + 1][2] in _JCC_RELOP_TRUE
        ):
            # A second relational term materializes directly into AX with no
            # dispatch pair (no orax self-test/jcc/jmp) -- immediately
            # combined with an earlier, INDEPENDENTLY materialized value
            # already stashed in BX via the generic andaxbx/oraxbx fold that
            # follows (wild process.exe/tamstart.exe): `V = (term1) AND
            # (term2)` used as a plain assignable value that's never
            # branched on, so TB skips the dispatch-tail template entirely
            # for BOTH terms (the first one already went through the
            # FP-relational-as-VALUE case below, landing in BX via the
            # generic movbxax right after). Distinct from the
            # direct_bool_gate case above, which is for a short-circuited
            # CODE-FLOW value, not two independently materialized terms.
            lhs, rhs = e.pend_cmp
            m.ax = ir.Group(
                ir.BinOp(_JCC_RELOP_TRUE[i.ops[c.k + 1][2]], lhs, rhs)
            )
            e.pend_cmp = None
            e.pend_cmp_str = False
            state.advance(3)
            return True
        # A STRING compare may take this path too, but ONLY inside an
        # ungrouped outer AND's right-hand group (direct_bool_gate): that is
        # the witnessed context -- t1_nestedbool's own right group reaches
        # here for each of its FP terms, and t1_boolstrgroup is the same
        # shape with string terms (wild tbd73.exe's TBWINDOW `SUB
        # Makevmenu`). Outside it, strings stay fail-loud as before; in
        # particular `V% = A$ = B$` (wild hebrew.exe) has no such gate and
        # still falls through to its own movm_ax branch below.
        # strcmp's flags are FORWARD, so the four ORDERING rows need
        # _JCC_RELOP_STR_TRUE, NOT _JCC_RELOP_TRUE's FP-reversed rows.
        _tmap = _JCC_RELOP_STR_TRUE if e.pend_cmp_str else _JCC_RELOP_TRUE
        if (
            (not e.pend_cmp_str or e.direct_bool_gate)
            and c.k + 3 < len(i.ops)
            and i.ops[c.k + 1][1] == "jcc"
            and i.ops[c.k + 2][1] == "incax"
            and i.ops[c.k + 1][3] == i.ops[c.k + 3][0]
            and i.ops[c.k + 1][2] in _tmap
            and i.ops[c.k + 3][1] not in ("orax", "andaxbx")
        ):
            # FP relational-as-VALUE inside arithmetic (t1_relval, wild
            # schart.exe): `(A > 0) * 3` materializes -1/0 into ax with no
            # dispatch pair after the inc -- the next op consumes ax directly
            # (imulbx/imul_m). The source REQUIRES the parens for this parse,
            # so the value carries an explicit Group -- and per-term parens
            # inside a logical group are a FREE normalization (oracle-checked:
            # `(A OR B)` and `((A) OR (B))` compile byte-identically).
            lhs, rhs = e.pend_cmp
            m.ax = ir.Group(
                ir.BinOp(_tmap[i.ops[c.k + 1][2]], lhs, rhs)
            )
            e.pend_cmp = None
            e.pend_cmp_str = False
            state.advance(3)
            return True
        if (
            e.pend_cmp_str
            and c.k + 3 < len(i.ops)
            and i.ops[c.k + 1][1] == "jcc"
            and i.ops[c.k + 2][1] == "incax"
            and i.ops[c.k + 1][3] == i.ops[c.k + 3][0]
            and i.ops[c.k + 1][2] in _JCC_RELOP_TRUE
            and (
                i.ops[c.k + 3][1] == "movm_ax"
                or (
                    c.k + 4 < len(i.ops)
                    and i.ops[c.k + 3][1] == "arg_ref"
                    and i.ops[c.k + 4][1] == "far_movm_ax_si"
                )
            )
        ):
            # String relational-as-VALUE assigned directly to a scalar
            # (`V% = A$ = B$`, wild hebrew.exe): materializes -1/0 into ax
            # with no dispatch pair, then stores AX either into a DS scalar
            # via movm_ax or a by-reference INTEGER via
            # arg_ref/far_movm_ax_si (v10_t1_strrelvalbyref; wild
            # process.exe). Unlike the FP case above, the whole
            # RHS IS the relational expression (there's no enclosing
            # arithmetic to disambiguate), so no Group wrapper is needed --
            # `V% = A$ = B$` parses the same with or without parens.
            lhs, rhs = e.pend_cmp
            m.ax = ir.BinOp(_JCC_RELOP_TRUE[i.ops[c.k + 1][2]], lhs, rhs)
            e.pend_cmp = None
            e.pend_cmp_str = False
            state.advance(3)
            return True
        _bx_term1 = m.bx.inner if isinstance(m.bx, ir.Group) else m.bx
        if (
            e.pend_cmp_str
            and isinstance(_bx_term1, (ir.RelOp, ir.BinOp))
            and (
                isinstance(_bx_term1, ir.RelOp)
                or _bx_term1.op in _JCC_RELOP_TRUE.values()
            )
            and c.k + 5 < len(i.ops)
            and i.ops[c.k + 3][1] == "andaxbx"
            and i.ops[c.k + 4][1] == "jcc"
            and i.ops[c.k + 5][1] == "jmp"
        ):
            # `(term1 AND term2) OR (term3 AND term4)` -- an explicitly
            # parenthesized AND-group used as one operand of an outer OR
            # (wild bmaster.exe/ifi.exe). Each group's OWN first term never
            # gets the usual self-test dispatch pair (no `or ax,ax`): TB
            # folds the group as a plain VALUE (materialize -> movbxax ->
            # materialize -> andaxbx) and reuses the group's OWN trailing
            # jcc/jmp as the shared decision point for the WHOLE OR --
            # jumping either into the next group (continue) or straight
            # into ITS closing jcc/jmp with ax already holding this group's
            # true short-circuit value (probe q_orofands). `m.bx` here
            # already holds term1's raw relation (via one of the SAME
            # no-dispatch-pair value paths used for a lone term -- a plain
            # BinOp for an integer/by-ref compare, e.g. t1_cmpfar, or a
            # Group-wrapped BinOp for the generic FP/LONG-icomp value
            # fallback above, e.g. wild bmaster.exe's SECOND group, a
            # `far_icomp_si32` term -- both unwrapped to `_bx_term1`) -- feed
            # it to `_lift_bool_tail` exactly as if `match_bool_term1` had
            # matched it, with a synthetic short-circuit target (there is no
            # real one to cross-check: this group's first term never had its
            # own dispatch). `_lift_bool_tail`'s existing scan-ahead loop
            # already recognizes the jmp landing on a SECOND group's own
            # andaxbx as a multi-term deferral, so the AND/OR/AND fold and
            # the outer OR join both fall out of the unmodified mechanism.
            r1 = (
                _bx_term1
                if isinstance(_bx_term1, ir.RelOp)
                else ir.RelOp(_bx_term1.op, _bx_term1.lhs, _bx_term1.rhs)
            )
            pb = BoolTerm(
                r1=r1,
                op="AND",
                sc=i.ops[c.k + 3][0] + 2,
                start=c.cur,
            )
            m.bx = None
            c.k, e.pend_bool, e.pend_bool_outer = _lift_bool_tail(
                i.ops,
                c.k,
                e.pend_cmp,
                pb,
                state.put,
                c.whiles,
                c.ifs,
                o.stmts,
                state.flush_pending,
                e.pend_bool_outer,
                wrap_group=True,
                branch=state.branch,
            )
            e.pend_cmp = None
            e.pend_cmp_str = False
            c.cur = None
            return True
        state.seek(_lift_while(
            i.ops,
            c.k,
            e.pend_cmp,
            c.whiles,
            c.dos,
            c.ifs,
            o.stmts,
            o.addrs,
            state.put,
            state.flush_pending,
            c.cur,
            block_ifs=c.block_if_addrs,
            branch=state.branch,
            # A backward jmp landing inside a body that is queued to be folded
            # is not a retry edge: the fold would have taken that address out
            # of the list before this question was asked.
            folded_away=state.folded_away,
            # And a `DO` spliced in ahead of a body moves every queued region
            # after it -- positions the eager fold had already collapsed.
            shift=state.shift_pending,
        ))
        e.pend_cmp = None
        e.pend_cmp_str = False
        c.cur = None
        return True
    if kind == "movax":  # int literal into ax
        # ``MOV AX,FFFF`` is the compiler's direct unsigned-token template
        # for `&HFFFF`; a source `-1` instead materializes one then negates.
        # Preserve the raw bit-pattern spelling for byte-exact re-emission
        # (tbd73's `IF REG(3) <> &HFFFF`).
        m.ax = ir.HexLit(op[2]) if op[2] >= 0x8000 else ir.Lit(op[2])
        state.advance()
        return True
    return False
