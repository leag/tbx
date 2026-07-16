"""Control-flow handlers: CALL, runtime dispatch, ON, error trap, strings, movax.

Handlers for ``decode_user_code``'s dispatch loop; each handler takes
the shared :class:`~tbx.decode0.core.DecodeState` plus the current
``op``/``addr``/``kind`` and returns ``True`` when it consumed the op.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from tbx import ir
from tbx.decode0.const import (
    _JCC_RELOP_TRUE,
    _JCC_RELOP_VALUE,
    _TRAP_CTL,
    _TRAP_GOSUB,
    _pp_commas,
)
from tbx.decode0.lift import (
    _lift_bool_tail,
    _lift_do_tail,
    _lift_while,
    _match_bool_term1,
)

if TYPE_CHECKING:
    from tbx.decode0.core import DecodeState


def calls(state: DecodeState, op, addr, kind) -> bool:
    """Dispatch family: call_abs, call_int, far_call, fn_call."""
    if kind == "call_abs":  # CALL ABSOLUTE addr
        state.put(ir.CallAbsolute(state.stack.pop()), state.cur)
        state.cur = None
        state.k += 1
        return True
    if kind == "call_int":  # CALL INTERRUPT n
        state.put(ir.CallInterrupt(state.ax), state.cur)
        state.ax = None
        state.cur = None
        state.k += 1
        return True
    if kind == "far_call":
        args = tuple(state.pend_args)
        state.pend_args.clear()
        state.put(ir.CallStmt(state.proc_names[op[2]], args), addr)
        state.cur = None
        state.k += 1
        return True
    if kind == "fn_call":  # drain staged args (offset order) -> FnCall
        args = tuple(state.fn_args[o] for o in sorted(state.fn_args))
        state.fn_args.clear()
        call = ir.FnCall(state.proc_names[op[2]], args)
        nxt = state.ops[state.k + 1] if state.k + 1 < len(state.ops) else None
        if nxt is not None and nxt[1] == "fnres_spush":
            # string FN: INT 9F pushes the result descriptor (t1_fnstr)
            state.sstack.append(call)
            state.k += 2
        else:
            state.stack.append(call)
            state.k += 1
        return True
    return False


def cargs(state: DecodeState, op, addr, kind) -> bool:
    """Dispatch family: arg_ref, arg_push_ref."""
    if kind == "arg_ref":  # les si,[bp+N]: by-ref param operand (offset)
        state.pend_arg = op[2]
        state.k += 1
        return True
    if kind == "arg_push_ref":  # push a by-ref CALL arg (caller's var)
        state.pend_args.append(state.loc(op[2]))
        state.k += 1
        return True
    return False


def runtime_call(state: DecodeState, op, addr, kind) -> bool:
    """Dispatch family: rt."""
    if kind == "rt":  # PRINT chains
        vec = op[2]
        if vec == 0xCA:  # USING begin: fmt off the sstack
            state.flush_pending()
            state.pend_using = {
                "fmt": state.sstack.pop(),
                "values": [],
                "file": None,
                "start": state.cur,
            }
            state.cur = None
            state.k += 1
            return True
        if vec in (0xCB, 0xCC):  # USING emit + its string item vec: CB formats a
            # numeric off the FP stack, CC a string off the sstack (t1_using)
            nxt = state.ops[state.k + 1][1:] if state.k + 1 < len(state.ops) else None
            if state.pend_using is None or nxt not in (("rt", 0xBE), ("rt", 0xC0)):
                raise ValueError(f"stray USING emit at {addr:#x}")
            f = None if nxt[1] == 0xBE else state.pend_fnum
            if nxt[1] == 0xC0 and f is None:
                raise ValueError(f"file USING item without [0060] at {addr:#x}")
            if state.pend_using["values"] and state.pend_using["file"] != f:
                raise ValueError(f"USING console/file leg flip at {addr:#x}")
            state.pend_using["file"] = f
            state.pend_using["values"].append(
                state.sstack.pop() if vec == 0xCC else state.stack.pop()
            )
            state.cur = None
            state.k += 2
            return True
        if vec == 0xC1:  # PRINT comma: zone-advance separator after an item
            if (
                state.pend_print is None
                or state.pend_print.get("mode")
                or not state.pend_print["items"]
            ):
                raise ValueError(f"comma separator without print item at {addr:#x}")
            state.pend_print.setdefault("commas", set()).add(
                len(state.pend_print["items"]) - 1
            )
            state.cur = None
            state.k += 1
            return True
        if vec in (0xBB, 0xBE, 0xBD, 0xC0):  # item-eval vectors
            if state.pend_using is not None:  # plain item closes a USING chain
                state.flush_pending()
            f = state.pend_fnum if vec in (0xBD, 0xC0) else None
            if vec in (0xBD, 0xC0) and f is None:
                raise ValueError(f"file print item without [0060] at {addr:#x}")
            if state.pend_print is not None and state.pend_print["file"] != f:
                state.flush_pending()  # console/file leg change = new stmt
            if state.pend_print is None:
                state.pend_print = {"items": [], "file": f, "start": state.cur}
            state.pend_print["items"].append(
                state.sstack.pop() if vec in (0xBE, 0xC0) else state.stack.pop()
            )
            state.cur = None
            state.k += 1
            return True
        if vec == 0xBC:  # LPRINT item-eval (printer)
            item = state.stack.pop()
            if (
                state.pend_print is not None
                and state.pend_print.get("mode") != "lprint"
            ):
                state.flush_pending()
            if state.pend_print is None:
                state.pend_print = {
                    "items": [],
                    "file": None,
                    "start": state.cur,
                    "mode": "lprint",
                }
            state.pend_print["items"].append(item)
            state.cur = None
            state.k += 1
            return True
        if vec == 0xB9:  # LPRINT flush-newline
            if state.pend_print is None or state.pend_print.get("mode") != "lprint":
                raise ValueError(f"b9 flush without open LPRINT chain at {addr:#x}")
            pp, state.pend_print = state.pend_print, None
            state.put(ir.Lprint(tuple(pp["items"])), pp["start"])
            state.cur = None
            state.k += 1
            return True
        if vec in (0xB8, 0xBA):  # flush-newline: statement complete
            want_file = vec == 0xBA
            if state.pend_using is not None:
                pu, state.pend_using = state.pend_using, None
                if (pu["file"] is not None) != want_file:
                    raise ValueError(f"USING flush leg mismatch at {addr:#x}")
                state.put(
                    ir.PrintUsing(
                        pu["fmt"],
                        tuple(pu["values"]),
                        file=pu["file"],
                        newline=True,
                    ),
                    pu["start"],
                )
            elif state.pend_print is not None:
                pp, state.pend_print = state.pend_print, None
                if (pp["file"] is not None) != want_file:
                    raise ValueError(f"print flush leg mismatch at {addr:#x}")
                if pp.get("mode") == "write":
                    state.put(
                        ir.Write(tuple(pp["items"]), file=pp["file"]), pp["start"]
                    )
                else:
                    state.put(
                        ir.Print(
                            tuple(pp["items"]),
                            file=pp["file"],
                            commas=_pp_commas(pp),
                        ),
                        pp["start"],
                    )
            elif not want_file:
                state.put(ir.Print(()), state.cur)  # bare PRINT (blank line)
            else:
                raise ValueError(f"file flush without items at {addr:#x}")
            if want_file:
                state.pend_fnum = None
            state.cur = None
            state.k += 1
            return True
        raise ValueError(f"unhandled runtime INT {vec:02x} at {addr:#x}")
    return False


def on_control(state: DecodeState, op, addr, kind) -> bool:
    """Dispatch family: on_goto, on_gosub."""
    if kind in ("on_goto", "on_gosub"):  # ON <sel> GOTO/GOSUB (EC sub 74/72)
        if state.ax is None:
            raise ValueError(f"ON without selector in ax at {addr:#x}")
        targets = tuple(("addr", t) for t in op[2:])
        cls = ir.OnGoto if kind == "on_goto" else ir.OnGosub
        state.put(cls(state.ax, targets), state.cur)
        state.ax = None
        state.cur = None
        state.k += 1
        return True
    return False


def errors_trap(state: DecodeState, op, addr, kind) -> bool:
    """Dispatch family: on_error, on_trap, error_stmt, resume_pre, trap_ctl, trap_hook."""
    if kind == "on_error":  # ON ERROR GOTO <line|0>
        state.put(ir.OnError(None if op[2] is None else ("addr", op[2])), state.cur)
        state.cur = None
        state.k += 1
        return True
    if kind == "on_trap":  # ON <event>[(n)] GOSUB <line>
        ev = _TRAP_GOSUB[op[2]]
        if ev == "TIMER":
            n = state.stack.pop()
        elif ev == "PEN":
            n = None
        else:
            n, state.ax = state.ax, None
        state.put(ir.OnTrap(ev, n, ("addr", op[3])), state.cur)
        state.cur = None
        state.k += 1
        return True
    if kind == "error_stmt":  # ERROR n
        state.put(ir.ErrorStmt(state.ax), state.cur)
        state.ax = None
        state.cur = None
        state.k += 1
        return True
    if kind == "resume_pre":  # RESUME [NEXT | <line>]
        nxt = state.ops[state.k + 1] if state.k + 1 < len(state.ops) else None
        if nxt is not None and nxt[1] == "resume_bare":
            node = ir.Resume()
        elif nxt is not None and nxt[1] == "resume_next":
            node = ir.Resume(next_=True)
        elif nxt is not None and nxt[1] in ("jmps", "jmp"):
            node = ir.Resume(target=("addr", nxt[2]))
        else:
            raise ValueError(f"RESUME tail {nxt} at {addr:#x} (unsupported)")
        state.put(node, state.cur)
        state.cur = None
        state.k += 2  # consume the form-selecting op
        return True
    if kind == "trap_ctl":  # <event>[(n)] ON|OFF|STOP
        ev, mode = _TRAP_CTL[op[2]]
        n = None
        if ev in ("COM", "KEY"):
            n, state.ax = state.ax, None
        state.put(ir.TrapCtl(ev, n, mode), state.cur)
        state.cur = None
        state.k += 1
        return True
    if kind == "trap_hook":  # per-statement event-poll hook:
        state.cc_hooks.add(state.cur)  # jump targets point at the hook,
        state.k += 1  # so cur (set above) stays put;
        return True
    return False


def string_ops(state: DecodeState, op, addr, kind) -> bool:
    """Dispatch family: strconcat, str_store_temp."""
    if kind == "strconcat":  # pops two strings, pushes concat
        rhs = state.sstack.pop()
        lhs = state.sstack.pop()
        state.sstack.append(ir.BinOp("+", lhs, rhs))
        state.k += 1
        return True
    if kind == "str_store_temp":  # CD A3: materialized string literal CALL arg
        state.pend_args.append(state.sstack.pop())
        state.cur = None
        state.k += 1
        return True
    return False


def movax_family(state: DecodeState, op, addr, kind) -> bool:
    """Ordered multi-branch dispatch family: movax."""
    if kind == "movax" and op[2] == 0xFFFF and state.pend_icmp is not None:
        # Relational-as-value: `cmp ax,[mem]; mov ax,FFFF; jcc cc; inc ax`.
        if (
            state.k + 2 >= len(state.ops)
            or state.ops[state.k + 1][1] != "jcc"
            or state.ops[state.k + 2][1] != "incax"
        ):
            raise ValueError(f"relational-value: expected jcc+incax at {addr:#x}")
        relop = _JCC_RELOP_VALUE.get(state.ops[state.k + 1][2])
        if relop is None:
            raise ValueError(f"relational-value: unmapped jcc at {addr:#x}")
        lhs, rhs = state.pend_icmp
        state.pend_icmp = None
        state.ax = ir.BinOp(relop, lhs, rhs)
        state.k += 3  # consume movax FFFF, jcc, incax
        return True
    if kind == "movax" and state.pend_cmp and op[2] == 0xFFFF:
        if state.pend_bool is not None:  # compound-IF tail
            state.k = _lift_bool_tail(
                state.ops,
                state.k,
                state.pend_cmp,
                state.pend_bool,
                state.put,
                state.whiles,
                state.ifs,
                state.stmts,
                state.flush_pending,
            )
            state.pend_bool = None
            state.pend_cmp = None
            state.cur = None
            return True
        comb = _match_bool_term1(state.ops, state.k)  # compound-IF first term?
        if comb is not None:
            state.pend_bool = {
                "r1": ir.RelOp(
                    _JCC_RELOP_TRUE[state.ops[state.k + 1][2]], *state.pend_cmp
                ),
                "op": comb,
                "sc": state.ops[state.k + 5][2],
                "start": state.cur,
            }
            state.pend_cmp = None
            state.k += 6
            return True
        nk = _lift_do_tail(
            state.ops,
            state.k,
            state.pend_cmp,
            state.stmts,
            state.addrs,
            state.put,
            state.cur,
        )  # DO..LOOP WHILE/UNTIL
        if nk is not None:
            state.k = nk
            state.pend_cmp = None
            state.cur = None
            return True
        state.k = _lift_while(
            state.ops,
            state.k,
            state.pend_cmp,
            state.whiles,
            state.dos,
            state.ifs,
            state.stmts,
            state.put,
            state.flush_pending,
            state.cur,
        )
        state.pend_cmp = None
        state.cur = None
        return True
    if kind == "movax":  # int literal into ax
        state.ax = ir.Lit(op[2] - 0x10000 if op[2] >= 0x8000 else op[2])
        state.k += 1
        return True
    return False
