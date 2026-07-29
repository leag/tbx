"""Control-flow handlers: CALL, runtime dispatch, ON, error trap, strings, movax.

Handlers for ``decode_user_code``'s dispatch loop; each handler takes
the shared :class:`~tbx.decode0.core.DecodeState` plus the current
``op``/``addr``/``kind`` and returns ``True`` when it consumed the op.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from tbx import ir
from tbx.decode0.frames import BoolTerm, PrintChain
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
    array_param_suffix,
    match_bool_outer_and_group,
    match_bool_term1,
    match_using_emit,
)

if TYPE_CHECKING:
    from tbx.decode0.core import DecodeState

def calls(state: DecodeState, op, addr, kind) -> bool:
    """Dispatch family: call_abs, call_int, far_call, fn_call."""
    img, m, e, l, c = (state.image, state.machine, state.expr,
                       state.layout_state, state.control)
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
        args = []
        for i, a in enumerate(c.pend_args):
            if isinstance(a, tuple) and a[0] == "fwd":
                # Forwarded by-ref param (arg_push_fwd): the far pointer pair
                # carries no type, so take it from the callee's param in the
                # same position -- and mark the enclosing SUB's param with the
                # same type so both headers agree (q_fwd).
                params = c.proc_params.get(op[2])
                if params is None:
                    # CALL to a SUB defined LATER in the file: the callee's
                    # own param list isn't known yet either. Stage a second
                    # placeholder (alongside the CallStmt name's own
                    # ("addr", n) one below), resolved together once every
                    # SUB has been decoded (wild resume.exe, extending the
                    # existing forward-CALL machinery to forwarded args).
                    args.append(("fwdpending", op[2], i, a[1]))
                    continue
                if op[2] in c.inline_procs:
                    # A SUB ... INLINE declares no parameter list at all, yet
                    # TB happily passes it arguments -- the $INLINE bytes read
                    # them off the stack themselves (TBWINDOW's `SUB Openbox
                    # INLINE` takes fifteen). So there is no callee signature to
                    # take the type from; fall back to what the ENCLOSING SUB
                    # already knows about this very parameter (probe
                    # t1_fwdinline; wild tbd73.exe).
                    off = a[1]
                    c.fwd_inline_offs.add(off)  # reconciled at proc_ret,
                    # once the enclosing SUB's own param types are settled --
                    # the call can precede every other use of the parameter,
                    # so its suffix is not knowable yet
                    args.append(ir.Var(f"P{off:02X}"))
                    continue
                if i >= len(params):
                    raise ValueError(
                        f"forwarded arg to unknown callee params at {addr:#x}"
                    )
                sfx = params[i][-1] if params[i][-1] in "%$" else ""
                off = a[1]
                if sfx == "%":
                    c.proc_int_offs.add(off)
                elif sfx == "$":
                    c.proc_str_offs.add(off)
                args.append(ir.Var(f"P{off:02X}{sfx}"))
            elif isinstance(a, tuple) and a[0] == "argref":
                # A caller-side scalar only ever touched via this by-ref
                # push (arg_push_ref's own ValueError deferral, above):
                # take its type from the callee's param in the same
                # position, same deferred-resolution shape as "fwd".
                params = c.proc_params.get(op[2])
                off = a[1]
                if params is None:
                    # Retain the layout spelling for a target that later turns
                    # out to be INLINE: it has no signature to supersede that
                    # fallback during final resolution.
                    args.append(("argrefpending", op[2], i, off, state.loc(off)))
                    continue
                if op[2] in c.inline_procs:
                    # An INLINE SUB has no declared parameter list, so it
                    # cannot type a guessed caller-side slot. Preserve the
                    # layout spelling; this is the same no-signature case
                    # handled above for forwarded frame parameters (tbd73's
                    # Openbox call).
                    args.append(state.loc(off))
                    continue
                if i >= len(params):
                    raise ValueError(
                        f"by-ref arg to unknown callee params at {addr:#x}"
                    )
                sfx = params[i][-1] if params[i][-1] in "%$&#" else ""
                if sfx == "%":
                    l.lay["scalars"][off] = 2
                elif sfx == "&":
                    l.lay["scalars"][off] = 4
                    l.lay["long_slots"].add(off)
                elif sfx == "#":
                    l.lay["scalars"][off] = 8
                elif sfx == "$":
                    l.lay["strs"].add(off)
                else:  # no suffix: TB's default (SINGLE) type
                    l.lay["scalars"][off] = 4
                args.append(state.loc(off))
            else:
                args.append(a)
        c.pend_args.clear()
        # A CALL to a SUB defined LATER in the file (address-ascending scan
        # order) hasn't had its proc_ret processed yet, so proc_names has no
        # entry for it (wild process.exe: SUB-to-SUB calls going both
        # directions). Stage the raw target address as a placeholder,
        # resolved once every SUB has been decoded (state._resolve_calls,
        # the CallStmt sibling of ir.Restore's block-index epilogue
        # resolution).
        name = c.proc_names.get(op[2], ("addr", op[2]))
        # c.cur, not addr: under active event trapping a CC poll hook
        # precedes this op and claims c.cur as the statement's own
        # address (trap_hook's handler, above) -- addr is the far_call
        # instruction's OWN position, one hook-op later, which silently
        # mismatched OutputState.cc_hooks and corrupted $EVENT ON/OFF metadata
        # recovery (t1_fargosub). Without a preceding hook the two already
        # coincide, so this is a pure correctness fix, not a behavior change
        # for any already-passing fixture.
        state.put(ir.CallStmt(name, tuple(args)), c.cur if c.cur is not None else addr)
        c.cur = None
        state.advance()
        return True
    if kind == "fn_call":  # drain staged args (offset order) -> FnCall
        args = tuple(c.fn_args[o] for o in sorted(c.fn_args))
        c.fn_args.clear()
        # A DEF FN body may appear later in the op stream. Mirror forward
        # CallStmt staging and resolve the immutable expression during final
        # program resolution once every definition has been named.
        name = c.proc_names.get(op[2], ("addr", op[2]))
        call = ir.FnCall(name, args)
        nxt = img.ops[c.k + 1] if c.k + 1 < len(img.ops) else None
        if nxt is not None and nxt[1] == "fnres_spush":
            # string FN: INT 9F pushes the result descriptor (t1_fnstr)
            e.sstack.append(call)
            state.advance(2)
        else:
            e.stack.append(call)
            state.advance()
        return True
    return False


def cargs(state: DecodeState, op, addr, kind) -> bool:
    """Dispatch family: arg_ref, arg_push_ref."""
    i, l, c = state.image, state.layout_state, state.control
    if kind == "arg_ref":  # les si,[bp+N]: by-ref param operand (offset)
        if c.cur is None:
            # A statement whose FIRST op is a by-ref param operand has to
            # anchor its own address here: this family returns early, before
            # core.py's generic top-of-statement `c.cur = addr` fallback,
            # so otherwise the statement would be recorded at its SECOND op.
            # That misses a loop-back edge landing on the arg_ref -- a head-
            # test `WHILE MID$(S$, X%, 1) <> "1"` over by-ref params reads its
            # string param first, and _has_jmps_back then fails to match the
            # `jmps` target against the test address, so _lift_while
            # misclassifies the loop as an inline-IF body skip and the
            # backward jmps has nothing left to close (t1_whmidref; wild
            # tbd73.exe's TBWINDOW `SUB Makevmenu`). Same anchoring the
            # mov_mem_sp branch below already does for the same reason.
            c.cur = addr
        c.pend_arg = op[2]
        state.advance()
        return True
    if kind == "arg_push_ref":  # push a by-ref CALL arg (caller's var)
        try:
            if op[2] in l.lay.get("guessed", ()):
                # Layout placed this slot but GUESSED its width -- its phantom-
                # slot bridge assigns 2 bytes to a disp with no direct-access
                # evidence, and a variable only ever forwarded by reference has
                # none. Spelling it `%` on that guess emits an argument whose
                # type disagrees with the callee's parameter, which TB rejects:
                # `Error 475: Parameter mismatch`. Take the same deferral as a
                # slot layout never placed at all (below) and let the callee's
                # own signature type it (fixture t1_byrefonlyarg; wild
                # tbd73.exe, whose CALLs pass several such variables).
                raise ValueError("by-ref slot width was guessed, not evidenced")
            c.pend_args.append(state.loc(op[2]))
        except ValueError:
            # The disp is never accessed any other way in this program --
            # only ever forwarded by address to a callee -- so layout's
            # evidence-gathering pass (which infers scalar/array shape from
            # direct read/write op patterns) has no type signal for it.
            # Defer, mirroring arg_push_fwd's own "fwd" placeholder: the
            # callee's own param list (known once its SUB has been decoded)
            # supplies the type (wild rsltest.exe: TBMENU.INC's MAKEMENU is
            # dead code, so its SHARED globals are only ever touched via
            # exactly this by-ref relay into MakeWindow).
            c.pend_args.append(("argref", op[2]))
        state.advance()
        return True
    if kind == "arg_push_array_bp":  # forward a whole-array PARAMETER onward
        # as a whole-array CALL argument. The relaying SUB never touches an
        # element, so the ordinary element-access path that registers (and
        # types) an array parameter never runs -- register it here from the
        # descriptor's own frame offset, the same `blk` that path keys on.
        # A pure relay carries no element-type evidence at all, so the name
        # stays unsuffixed; the callee's own signature is where the type
        # lives (probe t1_arrfwd, verified byte-exact either way).
        if c.proc_frame is None:
            raise ValueError(f"whole-array parameter push outside a SUB at {addr:#x}")
        if c.cur is None:
            c.cur = addr  # this push may OPEN the CALL statement -- see the
            # `sub_sp` anchor in handlers.arith for the same reasoning. With few
            # enough arguments TB pushes them directly instead of reserving an
            # outgoing area first, so the array push, not `sub sp,N`, is the
            # statement's first op (t1_ifbeforecall: an inline IF whose skip
            # target is the CALL that follows it).
        rec = c.proc_frame.array_params.setdefault(op[2], {"rank": 1})
        # A pure relay carries no element-type evidence, but the SAME procedure
        # may also index the array -- and then the type IS knowable and the
        # spelling matters: for a STRING array `A$()` and `A()` are different
        # variables and recompile to different bytes. So look ahead for a typed
        # element access before falling back to the unsuffixed name (wild
        # tbd73.exe's TBWINDOW `SUB Makehmenu` both forwards item$() onward and
        # indexes it; t1_arrfwd's numeric array needs no suffix either way,
        # which is why the unsuffixed fallback was byte-exact there).
        rec.setdefault(
            "name",
            f"P{op[2]:02X}"
            + array_param_suffix(i.ops, c.k, op[2]),
        )
        c.pend_args.append(ir.ArrayRef(rec["name"], ()))
        state.advance()
        return True
    if (
        kind == "movdx"
        and c.k + 1 < len(i.ops)
        and i.ops[c.k + 1][1] == "movdsdx"
        and c.k
        and i.ops[c.k - 1][1] == "arg_push_array_bp"
    ):  # mov dx,<DGROUP>; mov ds,dx -- restores DS after the push above
        state.advance(2)  # pointed it at the stack segment. Semantic-free glue.
        return True
    if kind == "arg_push_ref_bp":  # push a by-ref CALL arg, LOCAL-frame
        c.pend_args.append(state.loc_local(op[2]))  # caller's var
        state.advance()
        return True
    if kind == "arg_push_fwd":  # forward the enclosing SUB's by-ref param as a
        # CALL arg; typed at far_call from the callee's signature (q_fwd)
        c.pend_args.append(("fwd", op[2]))
        state.advance()
        return True
    return False


def runtime_call(state: DecodeState, op, addr, kind) -> bool:
    """Dispatch family: rt."""
    i, e, c = state.image, state.expr, state.control
    if kind == "rt":  # PRINT chains
        vec = op[2]
        if vec == 0xCA:  # USING begin: fmt off the sstack
            state.flush_pending()
            e.pend_using = {
                "fmt": e.sstack.pop(),
                "values": [],
                "file": None,
                "start": c.cur,
            }
            c.cur = None
            state.advance()
            return True
        if vec in (0xCB, 0xCC):  # USING emit + its string item vec: CB formats a
            # numeric off the FP stack, CC a string off the sstack (t1_using);
            # item vec BE = console, C0 = file, BF = printer (LPRINT USING,
            # witnessed t1_lpusing / wild vhfprop.exe)
            emit = match_using_emit(i.ops, c.k)
            if e.pend_using is None or emit is None:
                raise ValueError(f"stray USING emit at {addr:#x}")
            lp = emit.leg == "printer"
            f = e.pend_fnum if emit.leg == "file" else None
            if emit.leg == "file" and f is None:
                raise ValueError(f"file USING item without [0060] at {addr:#x}")
            if e.pend_using["values"] and (
                e.pend_using["file"] != f
                or e.pend_using.get("lprint", False) != lp
            ):
                raise ValueError(f"USING console/file leg flip at {addr:#x}")
            e.pend_using["file"] = f
            e.pend_using["lprint"] = lp
            e.pend_using["values"].append(
                e.stack.pop() if emit.numeric else e.sstack.pop()
            )
            c.cur = None
            state.advance(2)
            return True
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
            if e.pend_using is not None:  # plain item closes a USING chain
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
        if vec in (0xBC, 0xBF):  # LPRINT item-eval (printer): BC numeric off the
            # FP stack, BF string off the sstack (witnessed t1_lpstr)
            item = e.sstack.pop() if vec == 0xBF else e.stack.pop()
            if e.pend_using is not None:  # plain item closes a USING chain
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
            if e.pend_using is not None:  # LPRINT USING closes on B9 too
                pu, e.pend_using = e.pend_using, None
                if not pu.get("lprint"):
                    raise ValueError(f"b9 flush of a non-printer USING at {addr:#x}")
                state.put(
                    ir.PrintUsing(
                        pu["fmt"],
                        tuple(pu["values"]),
                        newline=True,
                        lprint=True,
                    ),
                    pu["start"],
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
                raise ValueError(f"b9 flush without open LPRINT chain at {addr:#x}")
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
            if e.pend_using is not None:
                pu, e.pend_using = e.pend_using, None
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


def errors_trap(state: DecodeState, op, addr, kind) -> bool:
    """Dispatch family: on_error, on_trap, error_stmt, resume_pre, trap_ctl, trap_hook."""
    i, m, e, c, o = state.image, state.machine, state.expr, state.control, state.output
    if kind == "on_error":  # ON ERROR GOTO <line|0>
        state.put(ir.OnError(None if op[2] is None else ("addr", op[2])), c.cur)
        c.cur = None
        state.advance()
        return True
    if kind == "on_trap":  # ON <event>[(n)] GOSUB <line>
        ev = _TRAP_GOSUB[op[2]]
        if ev == "TIMER":
            n = e.stack.pop()
        elif ev == "PEN":
            n = None
        else:
            n, m.ax = m.ax, None
        state.put(ir.OnTrap(ev, n, ("addr", op[3])), c.cur)
        c.cur = None
        state.advance()
        return True
    if kind == "error_stmt":  # ERROR n
        state.put(ir.ErrorStmt(m.ax), c.cur)
        m.ax = None
        c.cur = None
        state.advance()
        return True
    if kind == "resume_pre":  # RESUME [NEXT | <line>]
        nxt = i.ops[c.k + 1] if c.k + 1 < len(i.ops) else None
        if nxt is not None and nxt[1] == "resume_bare":
            node = ir.Resume()
        elif nxt is not None and nxt[1] == "resume_next":
            node = ir.Resume(next_=True)
        elif nxt is not None and nxt[1] in ("jmps", "jmp"):
            node = ir.Resume(target=("addr", nxt[2]))
        elif nxt is not None and nxt[1] == "run":
            # RESUME <line>, where <line> is the program's very FIRST
            # statement: the target address coincides exactly with a bare
            # RUN's own jump-to-start byte pattern (TB 1.0's E9-near form
            # canonicalizes any target == start+3, the first statement's
            # own address, regardless of source construct), so the
            # scanner tags it "run" instead of jmp/jmps (wild
            # styllist.exe, probe q_resumestart3). RESUME can never
            # trigger a genuine full-reset RUN (that would erase the
            # error state it's resuming from), so this is always the
            # plain first-statement target, start+3 in both dialects.
            node = ir.Resume(target=("addr", i.start + 3))
        else:
            raise ValueError(f"RESUME tail {nxt} at {addr:#x} (unsupported)")
        state.put(node, c.cur)
        c.cur = None
        state.advance(2)  # consume the form-selecting op
        return True
    if kind == "trap_ctl":  # <event>[(n)] ON|OFF|STOP
        ev, mode = _TRAP_CTL[op[2]]
        n = None
        if ev in ("COM", "KEY"):
            n, m.ax = m.ax, None
        state.put(ir.TrapCtl(ev, n, mode), c.cur)
        c.cur = None
        state.advance()
        return True
    if kind == "trap_hook":  # per-statement event-poll hook:
        o.cc_hooks.add(c.cur)  # jump targets point at the hook,
        state.advance()  # so cur (set above) stays put;
        return True
    return False


def string_ops(state: DecodeState, op, addr, kind) -> bool:
    """Dispatch family: strconcat, str_store_temp."""
    e, c = state.expr, state.control
    if kind == "strconcat":  # pops two strings, pushes concat
        rhs = e.sstack.pop()
        lhs = e.sstack.pop()
        e.sstack.append(ir.BinOp("+", lhs, rhs))
        state.advance()
        return True
    if kind == "str_store_temp":  # CD A3: materialized string literal CALL arg
        c.pend_args.append(e.sstack.pop())
        c.cur = None
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
            c.cur = None
            return True
        # Use the legacy index as the source of truth while this handler still
        # shares the dispatch loop with non-cursor handlers.  The matcher is
        # pure, so this keeps recognition independent from cursor history.
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
            state.advance(6)
            return True
        if (
            match_bool_outer_and_group(i.ops, c.k) is not None
            and any(o[1] == "strcmp" for o in i.ops[c.k + 6 : c.k + 36])
        ):
            # The materialized left term of `A AND (B OR C)` is preserved
            # through BX/CX while the right group uses its own spill fold.
            m.ax = ir.RelOp(_JCC_RELOP_TRUE[i.ops[c.k + 1][2]], *e.pend_cmp)
            e.pend_cmp = None
            e.pend_cmp_str = False
            e.direct_bool_gate = True
            e.direct_bool_logical = True
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
        )  # DO..LOOP WHILE/UNTIL
        if nk is not None:
            state.seek(nk)
            e.pend_cmp = None
            c.cur = None
            return True
        if (
            e.direct_bool_gate
            and m.bx is not None
            and not e.pend_cmp_str
            and c.k + 3 < len(i.ops)
            and i.ops[c.k + 1][1] == "jcc"
            and i.ops[c.k + 2][1] == "incax"
            and i.ops[c.k + 3][1] == "andaxbx"
            and i.ops[c.k + 1][3] == i.ops[c.k + 3][0]
            and i.ops[c.k + 1][2] in _JCC_RELOP_TRUE
        ):
            # The right side of `((a) OR (b)) AND (c)` is a single
            # parenthesized relation. It materializes directly into AX and is
            # immediately combined with the short-circuited left side in BX,
            # rather than using the normal six-op IF/loop tail template.
            lhs, rhs = e.pend_cmp
            m.ax = ir.Group(
                ir.BinOp(_JCC_RELOP_TRUE[i.ops[c.k + 1][2]], lhs, rhs)
            )
            e.pend_cmp = None
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
            and i.ops[c.k + 3][1] == "movm_ax"
        ):
            # String relational-as-VALUE assigned directly to a scalar
            # (`V% = A$ = B$`, wild hebrew.exe): materializes -1/0 into ax
            # with no dispatch pair, the next op stores ax straight into a
            # DS scalar via movm_ax. Unlike the FP case above, the whole
            # RHS IS the relational expression (there's no enclosing
            # arithmetic to disambiguate), so no Group wrapper is needed --
            # `V% = A$ = B$` parses the same with or without parens.
            lhs, rhs = e.pend_cmp
            m.ax = ir.RelOp(_JCC_RELOP_TRUE[i.ops[c.k + 1][2]], lhs, rhs)
            e.pend_cmp = None
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
