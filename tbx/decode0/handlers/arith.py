"""Integer and floating-point arithmetic / bit-op / stack handlers.

Handlers for ``decode_user_code``'s dispatch loop; each handler takes
the shared :class:`~tbx.decode0.core.DecodeState` plus the current
``op``/``addr``/``kind`` and returns ``True`` when it consumed the op.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from tbx import ir
from tbx.decode0.statement_log import editing
from tbx.decode0.matchers import (
    match_array_param_type,
    match_fn_result_readback,
    match_return_to,
)
from tbx.decode0.const import (
    ARR_BLOCK,
    _FREAD,
    _INPUTREAD,
    _JCC_RELOP_VALUE,
    _LINEINPUTREAD,
    _PREC,
    _READDATA,
)

from tbx.decode0.scan import _grp, _orient, _rgrp

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from tbx.decode0.core import DecodeState


def _next_real_addr(img, i):
    """The address of the next op after `i`, skipping toggle-instrumentation
    ops (`into`/`stack_chk`) that carry no source spelling and can land
    between any two ops under the Overflow/Stack-test IDE options -- so a
    positional adjacency check (e.g. "is this op immediately followed by the
    FOR's own NEXT test") has to look past them the same way the main
    dispatch loop's own generic `into`/`stack_chk` skip effectively does
    (wild bill.exe: an Overflow-toggle `into` between a loop's closing
    `dec_m` and its `cmp_mi8` test broke the adjacency check that guards
    against a mid-body DECR hijacking the step, round 36's fix)."""
    while i < len(img.ops) and img.ops[i][1] in ("into", "stack_chk"):
        i += 1
    return img.ops[i][0] if i < len(img.ops) else None


def int_alu(state: DecodeState, op, addr, kind) -> bool:
    """Dispatch family: movdx_m, movdxax, movdxbx, movbxax, movaxdx, movrr, movsim, addax_m, addax_bp, addsiax, subax_m, imul_m, imul_bp, movax_bp, idivbx, cmpax_m, inc_m, dec_m, negax, notax, notdx, oraxdx, xorax, xorah, shlsi, movmem_ax, reg_set."""
    img, m, expr_, l, c, o = (state.image, state.machine, state.expr,
                              state.layout_state, state.control, state.output)
    if kind == "movdx_m":  # IMP left operand -> dx
        m.dx = state.loc(op[2])
        state.advance()
        return True
    if kind == "movdxax":  # WAIT/INP port: ax -> dx
        m.dx, m.ax = m.ax, None
        state.advance()
        return True
    if kind == "movdxbx":  # OUT port: bx -> dx
        m.dx, m.bx = m.bx, None
        state.advance()
        return True
    if kind == "movbxax":  # LOCATE row -> bx
        m.bx, m.ax = m.ax, None
        state.advance()
        return True
    if kind == "movaxdx":  # promote the \ quotient to MOD
        if not (isinstance(m.ax, ir.BinOp) and m.ax.op == "\\"):
            raise ValueError(f"movaxdx not following idiv at {addr:#x}")
        m.ax = ir.BinOp("MOD", m.ax.lhs, m.ax.rhs)
        state.advance()
        return True
    if kind == "movrr":  # spill-protocol shuttle
        regs = {
            "ax": m.ax,
            "bx": m.bx,
            "cx": m.cx,
            "dx": m.dx,
            "di": m.di,
            "si": m.si,
        }
        regs[op[2]], regs[op[3]] = regs[op[3]], None
        m.ax, m.bx, m.cx, m.dx, m.di, m.si = (
            regs["ax"],
            regs["bx"],
            regs["cx"],
            regs["dx"],
            regs["di"],
            regs["si"],
        )
        state.advance()
        return True
    if kind == "spill_store":
        value = {"di": m.di}[op[2]]
        if value is None:
            raise ValueError(f"empty {op[2]} spill at {addr:#x}")
        m.reg_spills[op[3]] = value
        m.di = None
        state.advance()
        return True
    if kind == "spill_load":
        try:
            value = m.reg_spills.pop(op[3])
        except KeyError:
            raise ValueError(f"unknown spill cell {op[3]:#x} at {addr:#x}") from None
        if op[2] == "cx":
            m.cx = value
        elif op[2] == "di":
            m.di = value
        else:
            raise ValueError(f"unsupported spill target {op[2]} at {addr:#x}")
        state.advance()
        return True
    if kind in ("movm_ax_temp", "movm_imm_temp"):
        # mov ss:[si],ax / mov ss:[si],imm16: a temp-frame argument store.
        # Two different callers drain this frame: a plain SUB CALL (an
        # `arg_push_temp` follows immediately, ordered list -> pend_args) or
        # a DEF FN call used AS another call's own argument (no
        # arg_push_temp -- the frame closes straight into `mov_bp_sp;
        # fn_call`, offset-keyed dict -> fn_args, keyed by the `si` offset
        # this store's own address computed, i.e. the future bp offset once
        # mov_bp_sp repoints bp here; t1_fnargcall). SUB CALL can't nest as
        # an argument (CALL is a statement, not an expression), so this
        # ordering split is exhaustive.
        value = ir.Lit(op[2]) if kind == "movm_imm_temp" else m.ax
        if kind == "movm_ax_temp" and m.ax is None:
            raise ValueError(f"empty integer temp argument at {addr:#x}")
        nxt = img.ops[c.k + 1] if c.k + 1 < len(img.ops) else None
        if nxt is not None and nxt[1] == "arg_push_temp":
            c.pend_args.append(value)
        else:
            c.fn_args[m.si] = value
        m.ax = None
        # No state.put() happens here -- this op stages one argument value
        # mid-expression, inside a CALL/DEF-FN-call statement that's still
        # open (its own address was already set when IT started, e.g. by
        # the far-CALL argument-staging prologue). Clearing c.cur here
        # unconditionally let the generic top-of-loop fallback re-stamp it
        # with a LATER op's address once more ops ran, so the eventual
        # far_call's put() recorded the wrong statement address -- a loop's
        # own backward branch targeting the CALL's real start (its
        # mov_mem_sp/push_bp prologue) then failed to resolve to any
        # tracked statement (wild morcalc.exe).
        state.advance()
        return True
    if kind == "movsim":
        # mov si,[disp16]: FOR-loop variable as a raw element index.
        m.si = state.loc(op[2])
        state.advance()
        return True
    if kind == "movsi_bp":
        # mov si,[bp+d8]: LOCAL int as a raw element index (q_locidx)
        m.si = state.loc_local(op[2])
        state.advance()
        return True
    if kind == "addax_m":  # fold LEFT; neg-aware = subtraction
        try:
            mem = state.loc(op[2])
        except ValueError:
            if op[2] < l.lay["pool_base"] - 4:
                raise
            # pooled int-literal LEFT operand: `15 - LEN(A$)` evaluates the
            # computed RIGHT first, negates, then adds the literal from the
            # const pool (witnessed t1_addpool) -- same fallback fpval/ifold
            # already have.
            mem = state.pool_lit(op[2])
        if isinstance(m.ax, ir.Neg):
            m.ax = ir.BinOp("-", mem, _rgrp("-", m.ax.operand))
        else:
            m.ax = ir.BinOp("+", mem, _rgrp("+", m.ax))
        state.advance()
        return True
    if kind == "addax_bp":  # large-LOCAL sibling of addax_m
        mem = state.loc_local(op[2])
        if isinstance(m.ax, ir.Neg):
            m.ax = ir.BinOp("-", mem, _rgrp("-", m.ax.operand))
        else:
            m.ax = ir.BinOp("+", mem, _rgrp("+", m.ax))
        state.advance()
        return True
    if kind == "addsiax":
        # accumulate index legs, highest dim first (column-major):
        # rank 2: si=jspan + ax=i -> idx(i, j)
        # rank 3: si=kspan + ax=jspan -> jk(j, k); si=jk + ax=i -> idx(i, j, k)
        # (rank-3 witnessed t1_dim3v)
        # rank 4: si=lspan + ax=kspan -> kl(k, l); si=kl + ax=jspan -> jkl(j, k, l);
        # si=jkl + ax=i -> idx(i, j, k, l) (wild hfprop.exe, probe q_dim4var)
        if (
            isinstance(m.si, tuple)
            and m.si[0] == "lspan"
            and isinstance(m.ax, tuple)
            and m.ax[0] == "kspan"
            and m.ax[1] == m.si[1]
        ):
            m.si = ("kl", m.si[1], (m.ax[2], m.si[2]))
            m.ax = None
            state.advance()
            return True
        if (
            isinstance(m.si, tuple)
            and m.si[0] == "kl"
            and isinstance(m.ax, tuple)
            and m.ax[0] == "jspan"
            and m.ax[1] == m.si[1]
        ):
            m.si = ("jkl", m.si[1], (m.ax[2], *m.si[2]))
            m.ax = None
            state.advance()
            return True
        if (
            isinstance(m.si, tuple)
            and m.si[0] == "kspan"
            and isinstance(m.ax, tuple)
            and m.ax[0] == "jspan"
            and m.ax[1] == m.si[1]
        ):
            m.si = ("jk", m.si[1], (m.ax[2], m.si[2]))
            m.ax = None
            state.advance()
            return True
        if not (isinstance(m.si, tuple) and m.si[0] in ("jspan", "jk", "jkl")):
            raise ValueError(f"add si,ax with si={m.si} ax={m.ax} at {addr:#x}")
        if (
            isinstance(m.ax, tuple)
            and m.ax[0] == "inorm"
            and m.ax[1] == m.si[1]
        ):
            i_expr = m.ax[2]
        elif not isinstance(m.ax, tuple) and m.ax is not None:
            i_expr = m.ax  # base-0: no i-lo sub
        else:
            raise ValueError(f"add si,ax with si={m.si} ax={m.ax} at {addr:#x}")
        rest = m.si[2] if m.si[0] in ("jk", "jkl") else (m.si[2],)
        m.si = ("idx", m.si[1], (i_expr, *rest))
        m.ax = None
        state.advance()
        return True
    if kind == "subax_m":
        blk = next((b for b in l.slot_info if b <= op[2] < b + ARR_BLOCK), None)
        if blk is None:
            # Not a far-IDX lo-subscript normalization cell -- a plain
            # subtraction fold instead (`<expr> - <mem>`), mem on the
            # RIGHT (unlike addax_m's mem-LEFT convention, since SUB
            # isn't commutative and `sub ax,[mem]` computes ax-mem
            # directly). Same pool-literal fallback as addax_m/imul_m
            # (wild resume.exe).
            try:
                mem = state.loc(op[2])
            except ValueError:
                if op[2] < l.lay["pool_base"] - 4:
                    raise
                mem = state.pool_lit(op[2])
            if isinstance(m.ax, tuple) or m.ax is None:
                raise ValueError(f"sub ax,[{op[2]:#x}] with non-Expr ax at {addr:#x}")
            m.ax = ir.BinOp("-", m.ax, _rgrp("-", mem))
            state.advance()
            return True
        off = op[2] - blk
        if isinstance(m.ax, tuple) or m.ax is None:
            raise ValueError(f"far-IDX normalization of non-Expr ax at {addr:#x}")
        if off in (0x0E, 0x14):  # j - lo2 (or k - lo3), then * cumulative span
            span_off = 0x0C if off == 0x0E else 0x12  # span1 / span2 cell
            if (
                c.k + 1 >= len(img.ops)
                or img.ops[c.k + 1][1] != "imul_m"
                or img.ops[c.k + 1][2] != blk + span_off
            ):
                raise ValueError(f"jspan without imul at {addr:#x}")
            l.slot_info[blk]["subful"] = True  # lo-sub witness
            m.ax = ("jspan" if off == 0x0E else "kspan", blk, m.ax)
            state.advance(2)
            return True
        if off == 0x08:  # i - lo1
            l.slot_info[blk]["subful"] = True  # lo-sub witness
            m.ax = ("inorm", blk, m.ax)
            state.advance()
            return True
        raise ValueError(f"sub ax from unexpected cell offset {off:#x} at {addr:#x}")
    if kind == "imul_m":
        blk = next(
            (b for b in l.slot_info if op[2] in (b + 0x0C, b + 0x12, b + 0x18)),
            None,
        )
        if blk is not None:  # bare span multiply: OPTION BASE 0
            if isinstance(m.ax, tuple) or m.ax is None:  # far-IDX j-leg
                raise ValueError(f"span imul of non-Expr ax at {addr:#x}")
            off = op[2] - blk
            m.ax = (
                {0x0C: "jspan", 0x12: "kspan", 0x18: "lspan"}[off],  # span3
                blk,  # (dim 4, wild hfprop.exe): t1_dim3v/t1_dim4v
                m.ax,
            )
        else:
            try:
                mem = state.loc(op[2])
            except ValueError:
                if op[2] < l.lay["pool_base"] - 4:
                    raise
                # pooled int-literal LEFT operand: `180 * (A > 0)` evaluates
                # the materialized right first, then multiplies the literal
                # from the const pool (witnessed t1_imulpool, wild schart.exe)
                mem = state.pool_lit(op[2])
            m.ax = ir.BinOp("*", mem, _rgrp("*", m.ax))
        state.advance()
        return True
    if kind == "imul_bp":  # imul word [bp+d8]: LOCAL int as the right operand
        m.ax = ir.BinOp("*", state.loc_local(op[2]), _rgrp("*", m.ax))
        state.advance()
        return True
    if kind == "movax_bp":  # mov ax, [bp+d8]: LOCAL int read, e.g. as an
        # expression's first term (t1_byref1) -- OR, at bp+0 right after a
        # fn_call, the caller reading back a just-called integer FN's result
        # from the shared staged frame (fn_call always stages the FnCall node
        # onto the float-oriented `expr_.stack`; this is that value's
        # ax-register sibling -- wild resume.exe). `mov_bp_sp` has repointed BP
        # at the staging frame by then, so the enclosing SUB's own LOCAL frame
        # is NOT what bp+0 means here: keying on the preceding fn_call rather
        # than on "no frame is open" is what lets an integer FN be called from
        # inside a SUB body at all (probe t1_fnintcall; wild tbd73.exe, whose
        # TBWINDOW SUBs call FNAttr() -- integer-typed under its DEFINT a-z).
        # The fn_call need not be the IMMEDIATELY preceding op: when the
        # result is about to be compared, the comparison's other operand was
        # evaluated BEFORE the call and is shuttled into bx right after it
        # (`IF FNCurvideo <> 7 THEN` -- wild tbd73.exe, TBW73.INC:339 -- puts
        # the 7 in ax, calls, then `movbxax` banks it before `mov ax,[bp+0]`
        # reads the result). Skip that register-shuttle boilerplate, and
        # require an integer FnCall result to actually be waiting on the
        # stack, which is what makes the skip safe rather than a guess.
        if (
            match_fn_result_readback(img.ops, c.k) is not None
            and expr_.stack
            and isinstance(expr_.stack[-1], ir.FnCall)
        ):
            m.ax = expr_.stack.pop()
        else:
            m.ax = state.loc_local(op[2])
        state.advance()
        return True
    if kind == "idiv_m":  # ax (dividend) \ [disp16] (memory divisor)
        try:
            divisor = state.loc(op[2])
        except ValueError:
            divisor = ir.Var(f"V{op[2]:04X}")
        m.ax = ir.BinOp("\\", m.ax, _rgrp("\\", divisor))
        state.advance()
        return True
    if kind == "idivbx":  # ax (dividend) \ bx (divisor) -> ax
        if m.bx is None:
            logger.warning("idivbx without materialized divisor at %x", addr)
            m.bx = ir.Var("V_DIV")
        m.ax = ir.BinOp("\\", m.ax, _rgrp("\\", m.bx))
        m.bx = None
        state.advance()
        return True
    if kind == "cmpax_m":  # integer relational, mem side = source LHS
        if op[2] == 0x74:  # runtime cells, not user slots: ERR = [0074],
            mem: Any = ir.Err()  # ERL = [0072] (IF ERR = n, witnessed
        elif op[2] == 0x72:  # t1_errcmp / wild inv87.exe)
            mem = ir.Erl()
        else:
            try:
                mem = state.loc(op[2])
            except ValueError:
                if op[2] < l.lay["pool_base"] - 4:
                    mem = ir.Var(f"V{op[2]:04X}")
                else:
                    # pooled int-literal LEFT operand
                    mem = state.pool_lit(op[2])
        nxt = img.ops[c.k + 1] if c.k + 1 < len(img.ops) else None
        # AND-chain 2nd+ term (wild schart.exe): the running accumulator sits
        # in bx (OR-chains need no accumulator, they resolve by pure
        # short-circuit jumps -- t1_orchain). The compare's own flags survive
        # a plain register shuttle, so the compiler round-trips ax<->bx
        # (mov ax,bx; mov bx,ax -- a no-op restoring bx's value, byte-exact
        # boilerplate) between the compare and the value materialization;
        # skip over it and let the generic movrr/movbxax handlers process it.
        j = c.k + 1
        while j < len(img.ops) and img.ops[j][1] in ("movrr", "movbxax"):
            j += 1
        shuffled = (
            j > c.k + 1
            and j < len(img.ops)
            and img.ops[j][1] == "movax"
            and img.ops[j][2] == 0xFFFF
        )
        if (nxt is not None and nxt[1] == "movax" and nxt[2] == 0xFFFF) or shuffled:
            expr_.pend_icmp = (mem, m.ax)  # relational-value form
            m.ax = None
            state.advance()
            return True
        # IF forms: cmp ax,[mem] flags are rhs-lhs (REVERSED, like the FP
        # rows and unlike cmpax_bx's forward order) -- the skip map mirrors
        # cmpax_bp's and the direct map coincides with _JCC_RELOP_VALUE;
        # only "=" is witnessed (t1_errcmp direct, inv87 skip), the other
        # rows follow the same orientation derivation
        if nxt is not None and nxt[1] == "jcc":
            cc = nxt[2]
            j2 = img.ops[c.k + 2] if c.k + 2 < len(img.ops) else None
            if j2 is not None and j2[1] == "jmp" and nxt[3] == j2[0] + 3:
                skiprel = {
                    0x74: "<>", 0x75: "=", 0x7F: ">=",
                    0x7D: ">", 0x7C: "<=", 0x7E: "<",
                }
                if cc not in skiprel:
                    raise ValueError(f"cmpax_m IF jcc {cc:02x} at {addr:#x}")
                state.put(
                    ir.IfGoto(
                        ir.RelOp(skiprel[cc], mem, m.ax), ("addr", j2[2])
                    ),
                    c.cur,
                )
                m.ax = None
                c.cur = None
                state.advance(3)
                return True
            if cc in _JCC_RELOP_VALUE:  # direct: taken = THEN <line>
                state.put(
                    ir.IfGoto(
                        ir.RelOp(_JCC_RELOP_VALUE[cc], mem, m.ax),
                        ("addr", nxt[3]),
                    ),
                    c.cur,
                )
                m.ax = None
                c.cur = None
                state.advance(2)
                return True
        raise ValueError(f"cmpax_m without a value/IF consumer at {addr:#x}")
    if kind == "cmpm_ax":  # cmp [mem],ax outside the FOR/NEXT template
        if m.ax is None:
            raise ValueError(f"cmpm_ax without ax operand at {addr:#x}")
        expr_.pend_cmp = (state.loc(op[2]), m.ax)
        expr_.pend_cmp_str = False
        m.ax = None
        state.advance()
        return True
    if kind == "cmpax_bp":  # cmp ax,[bp+d8]: relational against a LOCAL int
        # (q_loccmp). The compiler evaluates the SOURCE RHS into ax and
        # compares the LOCAL as memory, so flags are rhs-vs-lhs; the emitted
        # skip-goto must keep the LOCAL on the LEFT (byte-identical respell),
        # which needs a mirrored negation map -- the shared _JCC_RELOP signed
        # rows assume cmpax_bx's forward flag order, so the IF form consumes
        # its own jcc+jmp here. Value form (movax FFFF follows) keeps
        # cmpax_m's (mem, ax) source order.
        nxt = img.ops[c.k + 1] if c.k + 1 < len(img.ops) else None
        local = state.loc_local(op[2])
        # AND-chain 2nd+ term (wild resume.exe): same ax<->bx no-op round
        # trip as cmpax_m's own AND-chain case above -- skip over it and
        # let the generic movrr/movbxax handlers process it.
        j = c.k + 1
        while j < len(img.ops) and img.ops[j][1] in ("movrr", "movbxax"):
            j += 1
        shuffled = (
            j > c.k + 1
            and j < len(img.ops)
            and img.ops[j][1] == "movax"
            and img.ops[j][2] == 0xFFFF
        )
        if (nxt is not None and nxt[1] == "movax" and nxt[2] == 0xFFFF) or shuffled:
            expr_.pend_icmp = (local, m.ax)
            m.ax = None
            state.advance()
            return True
        skiprel = {0x74: "<>", 0x75: "=", 0x7F: ">=", 0x7D: ">", 0x7C: "<=", 0x7E: "<"}
        if (
            nxt is None
            or nxt[1] != "jcc"
            or nxt[2] not in skiprel
            or c.k + 2 >= len(img.ops)
            or img.ops[c.k + 2][1] != "jmp"
            or nxt[3] != img.ops[c.k + 2][0] + 3
        ):
            raise ValueError(f"cmpax_bp without an IF jcc+skip-jmp at {addr:#x}")
        state.put(
            ir.IfGoto(
                ir.RelOp(skiprel[nxt[2]], local, m.ax),
                ("addr", img.ops[c.k + 2][2]),
            ),
            c.cur,
        )
        m.ax = None
        c.cur = None
        state.advance(3)
        return True
    if kind == "addax_bp":  # add ax,[bp+d8]: fold a LOCAL int LEFT (q_loccmp)
        if isinstance(m.ax, ir.Neg):
            m.ax = ir.BinOp(
                "-", state.loc_local(op[2]), _rgrp("-", m.ax.operand)
            )
        else:
            m.ax = ir.BinOp("+", state.loc_local(op[2]), _rgrp("+", m.ax))
        state.advance()
        return True
    if kind == "subax_bp":
        # Whole-array SUB parameters carry their declared lower bound at
        # descriptor offset +8. The machine subtraction normalizes the
        # address, but IR keeps the original source subscript.
        if c.proc_frame is None or c.k + 3 >= len(img.ops):
            raise ValueError(f"subax_bp outside array parameter at {addr:#x}")
        j = c.k + 1
        if img.ops[j][1] != "movsiax":
            raise ValueError(f"subax_bp without movsiax at {addr:#x}")
        while j + 1 < len(img.ops) and img.ops[j + 1][1] == "movrr":
            j += 1  # preserve a staged boolean/arithmetic accumulator in AX
            # while SI keeps this array subscript (wild zip.exe)
        while j + 1 < len(img.ops) and img.ops[j + 1][1] == "shlsi":
            j += 1
        if (
            j == c.k + 1
            or j + 1 >= len(img.ops)
            or img.ops[j + 1][1] != "moves_bp"
            or img.ops[j + 1][2] + 8 != op[2]
        ):
            raise ValueError(f"subax_bp array-parameter shape mismatch at {addr:#x}")
        rec = c.proc_frame.array_params.setdefault(
            img.ops[j + 1][2], {"rank": 1}
        )
        rec.setdefault("lo_off", op[2])  # `setdefault` on the DICT alone leaves
        # lo_off missing when a whole-array RELAY (arg_push_array_bp) registered
        # the descriptor first -- that path knows the name but not the index
        # base, and the element access here is where the base becomes known
        # (wild tbd73.exe's TBWINDOW `SUB Makehmenu`, which forwards item$()
        # onward AND indexes it; previously a raw KeyError on 'lo_off').
        state.advance()
        return True
    if kind == "andax_bp":  # and ax,[bp+d8]: bitwise fold of a LOCAL int,
        # the bp-relative sibling of andax_m (wild filepatc.exe)
        m.ax = ir.BinOp("AND", state.loc_local(op[2]), _rgrp("AND", m.ax))
        state.advance()
        return True
    if kind == "cmpax_bx":  # integer IF compare, both sides ax-computed: the
        # source RHS evaluates first and shuttles to bx, LHS lands in ax, and
        # the signed Jcc rides _JCC_RELOP's 7C-7F rows (witnessed t1_cmpax)
        expr_.pend_cmp = (m.ax, m.bx)
        expr_.pend_cmp_str = False  # replace any materialized string flags
        m.ax = m.bx = None
        state.advance()
        return True
    if kind == "inc_m":
        if c.fors and c.fors[-1].v == op[2]:
            # Integer FOR-NEXT increment -- implicit in BASIC; consume
            # silently (the NEXT stmt is emitted on the cmp_mi8 guard above).
            state.advance()
            return True
        # INCR normalization: bare INC [disp16] outside a FOR context
        # compiles `X = X + 1` (witnessed t1_incr1)
        var = state.loc(op[2])
        state.put(ir.Assign(var, ir.BinOp("+", var, ir.Lit(1))), c.cur)
        c.cur = None
        state.advance()
        return True
    if kind == "inc_bp":
        # LOCAL-var FOR-NEXT increment (q_locidx). Outside a FOR, `LOCAL X% =
        # X% + 1` instead compiles to addm_ax_bp (t1_local1) -- unlike the
        # DGROUP case, the two spellings are NOT byte-identical for a LOCAL
        # target, so a bare INCR statement decodes as its own `ir.Incr` node
        # rather than normalizing to an Assign (wild bmaster.exe/ifi.exe,
        # probe q_localincr3).
        if c.fors and c.fors[-1].v == op[2]:
            state.advance()
            return True
        state.put(ir.Incr(state.loc_local(op[2])), c.cur)
        c.cur = None
        state.advance()
        return True
    if kind == "dec_bp":
        # LOCAL-var STEP -1 FOR-NEXT decrement, the descending sibling of
        # inc_bp -- same step patch-up as dec_m's FOR branch (the header
        # folded a provisional Lit(1) step before this NEXT-side evidence
        # was available). Outside a FOR, this is TB's explicit `DECR var`
        # statement (the decrement sibling of `INCR`), NOT byte-identical
        # to `LOCAL X% = X% - 1` (a generic subtract) the way the DGROUP
        # case's two spellings are -- decodes as its own `ir.Decr` node
        # (wild horses.exe, probe q_localdecr).
        if (
            c.fors
            and c.fors[-1].v == op[2]
            and _next_real_addr(img, c.k + 1) == c.fors[-1].test
        ):
            f = c.fors[-1]
            old = o.stmts[f.idx]
            with editing(o.stmts, "patch_for_step"):
                state.patch(
                    f.idx, ir.For(old.var, old.init, old.limit, ir.Lit(-1))
                )
            f.step = -1
            state.advance()
            return True
        state.put(ir.Decr(state.loc_local(op[2])), c.cur)
        c.cur = None
        state.advance()
        return True
    if kind == "dec_m":
        # DECR normalization: bare DEC [disp16] compiles `X = X - 1`. Inside
        # an open FOR whose loop var this is, it's STEP -1's increment --
        # the descending sibling of inc_m (STEP +1), both special-cased
        # instead of the generic addm_i8 (any OTHER literal step). Same
        # placeholder-patch as addm_i8: the header folded a provisional
        # Lit(1) step before this NEXT-side evidence was available (wild
        # bill.exe).
        if (
            c.fors
            and c.fors[-1].v == op[2]
            and _next_real_addr(img, c.k + 1) == c.fors[-1].test
        ):
            f = c.fors[-1]
            old = o.stmts[f.idx]
            with editing(o.stmts, "patch_for_step"):
                state.patch(
                    f.idx, ir.For(old.var, old.init, old.limit, ir.Lit(-1))
                )
            f.step = -1
            state.advance()
            return True
        var = state.loc(op[2])
        state.put(ir.Assign(var, ir.BinOp("-", var, ir.Lit(1))), c.cur)
        c.cur = None
        state.advance()
        return True
    if kind == "addm_i8":
        # Integer FOR-NEXT increment for a literal STEP other than +-1 (those
        # use inc_m/dec_m instead): `add word [I%], step` at the open FOR's
        # test address. Rewrite the already-emitted ir.For statement's step
        # in place -- it was provisionally Lit(1) when the header was folded,
        # before this NEXT-side evidence was available (q_forstep/
        # q_forstepneg). Outside a FOR this is the multi-unit sibling of
        # inc_m: `X% = X% + literal` (wild number.exe).
        if not (
            c.fors
            and c.fors[-1].v == op[2]
            and _next_real_addr(img, c.k + 1) == c.fors[-1].test
        ):
            var = state.loc(op[2])
            state.put(ir.Assign(var, ir.BinOp("+", var, ir.Lit(op[3]))), c.cur)
            c.cur = None
            state.advance()
            return True
        f = c.fors[-1]
        old = o.stmts[f.idx]
        with editing(o.stmts, "patch_for_step"):
            state.patch(
                f.idx, ir.For(old.var, old.init, old.limit, ir.Lit(op[3]))
            )
        f.step = op[3]
        state.advance()
        return True
    if kind == "negax":  # subtraction setup
        m.ax = ir.Neg(m.ax)
        state.advance()
        return True
    if kind == "notax":  # unary NOT of the accumulator
        m.ax = ir.Not(m.ax)
        state.advance()
        return True
    if kind == "notdx":  # NOT the dx operand in place
        m.dx = ir.Not(m.dx)
        state.advance()
        return True
    if kind == "oraxdx":  # completes IMP as `(NOT A) OR B`
        m.ax = ir.BinOp("OR", m.dx, _rgrp("OR", m.ax))
        m.dx = None
        state.advance()
        return True
    if kind == "xorax":  # xor ax,ax = literal 0
        m.ax = ir.Lit(0)
        state.advance()
        return True
    if kind == "xorah":  # INP result widen: lift no-op
        state.advance()
        return True
    if kind == "shlsi":
        # `shl si[; shl si[; shl si]]; (moves_m blk | addsi base); <terminal>` --
        # one shl for a 2-byte (INTEGER) element stride (x2, wild number.exe:
        # the single-shl case had no witness until now, so the gate below
        # unconditionally required a second shl), two for 4-byte (single/
        # string-descriptor), the optional third for 8-byte (double).
        # An INTO (Overflow-toggle check, semantic-free) can land after ANY
        # arithmetic step in this chain -- each shl/addsi is itself
        # arithmetic that can overflow under the 'O' IDE Options toggle, and
        # its position varies by dialect (TB 1.1 puts it between the two
        # shl's; TB 1.0 puts one after the LAST shl and another after addsi,
        # right before the terminal consumer). Splicing it out at every join
        # point keeps every downstream `ao`-relative offset in this handler
        # valid, since it assumes strict shlsi/terminal adjacency otherwise
        # (wild mcmurphy.exe/rstprint.exe, probe q_ovfshl compiled with
        # --toggles O, byte-exact both dialects).
        def _skip_into(i):
            while i < len(img.ops) and img.ops[i][1] == "into":
                del img.ops[i]

        if (
            m.si is None
            and c.k + 2 < len(img.ops)
            and img.ops[c.k + 1][1] in ("shlsi", "into")
        ):
            # Address-only continuation after a computed array read; the
            # saved SI is rebuilt by the following runtime operation.
            state.advance(3)
            return True
        if m.si is None and c.k > 0 and img.ops[c.k - 1][1] == "far_movsi_si":
            logger.debug("ignoring helper index shift at %x", addr)
            state.advance()
            return True

        _skip_into(c.k + 1)
        if c.k + 1 >= len(img.ops):
            raise ValueError(f"shl si outside an element access at {addr:#x}")
        if img.ops[c.k + 1][1] == "shlsi":
            _skip_into(c.k + 2)
            if c.k + 2 < len(img.ops) and img.ops[c.k + 2][1] == "shlsi":
                _skip_into(c.k + 3)
                ao = 3
            else:
                ao = 2
        else:
            ao = 1
        _skip_into(c.k + ao)
        if c.k + ao + 1 >= len(img.ops) or img.ops[c.k + ao][1] not in (
            "moves_m",
            "moves_bp",  # LOCAL DYNAMIC array's ES load (probe q_localarr)
            "addsi",
        ):
            raise ValueError(f"shl si outside an element access at {addr:#x}")
        _skip_into(c.k + ao + 1)
        far = img.ops[c.k + ao][1] in ("moves_m", "moves_bp")
        if far:
            blk = img.ops[c.k + ao][2]
        else:  # near static: add si, <base>
            blk = next(
                (
                    b
                    for b, v in l.slot_info.items()
                    if v.get("base") == img.ops[c.k + ao][2]
                ),
                None,
            )
            if blk is None:
                raise ValueError(
                    f"add si,{img.ops[c.k + ao][2]:#x} matches no static "
                    f"base at {addr:#x}"
                )
        param_rec = (
            c.proc_frame.array_params.get(blk)
            if c.proc_frame is not None
            and img.ops[c.k + ao][1] == "moves_bp"
            else None
        )
        if not isinstance(m.si, tuple) and m.si is not None:
            # raw index in si: a plain subscript. 1-D, or a
            # Bounds checked access where the earlier dims were stashed in
            # bchk_subs (F3.5): si is the final (first-source) subscript, the
            # stash the rest in reverse (column-major collects dim-N..dim-1).
            if param_rec is not None:
                m.si = ("idx", blk, (m.si,))
            elif expr_.bchk_subs:
                subs = tuple(reversed(expr_.bchk_subs + [m.si]))
                expr_.bchk_subs = []
                if blk not in l.slot_info or l.slot_info[blk]["rank"] != len(
                    subs
                ):
                    raise ValueError(
                        f"bounds subscript count != array rank at {addr:#x}"
                    )
                m.si = ("idx", blk, subs)
            else:
                if blk not in l.slot_info or l.slot_info[blk]["rank"] != 1:
                    logger.warning(
                        "raw element index on non-rank-1 block %s at %x; "
                        "retaining first subscript",
                        hex(blk),
                        addr,
                    )
                m.si = ("idx", blk, (m.si,))
        if (
            not (isinstance(m.si, tuple) and m.si[0] == "idx")
            or m.si[1] != blk
        ):
            raise ValueError(f"shl si outside an element access at {addr:#x}")
        sik = img.ops[c.k + ao + 1]
        # A long-form computed element read can preserve the previously
        # materialized scalar in BX before loading the element (bmaster/ifi,
        # `movbxax; mov ax,[si]`).  The register move is glue, not the
        # element's terminal consumer; keep the element width in ``ao`` and
        # account for the extra op when consuming the chain.
        element_extra = 0
        if (
            sik[1] == "movrr"
            and c.k + ao + 3 < len(img.ops)
            and img.ops[c.k + ao + 2][1] == "movbxax"
        ):
            element_extra = 2
            sik = img.ops[c.k + ao + 3]
        elif (
            sik[1] == "movrr"
            and c.k + ao + 4 < len(img.ops)
            and img.ops[c.k + ao + 2][1] == "movrr"
            and img.ops[c.k + ao + 3][1] == "movbxax"
        ):
            element_extra = 3
            sik = img.ops[c.k + ao + 4]
        if sik[1] == "movbxax" and c.k + ao + 2 < len(img.ops):
            m.bx, m.ax = m.ax, None
            element_extra = 1
            sik = img.ops[c.k + ao + 2]
        if param_rec is not None:
            esz = 1 << ao
            suffix = (
                "$"
                if sik[1] in ("far_spush", "far_strassign")
                else "%"
                if sik[1] in ("far_fild_si", "far_fstp_si")
                else "&"
                if sik[1] in ("far_fild_si32", "far_fstp_si32")
                else "#"
                if esz == 8
                else ""
            )
            if sik[1] == "arg_push_arr" and "esz" not in param_rec:
                # This type-BLIND by-ref push is the FIRST access to the
                # descriptor, so there is no recorded type to keep (the branch
                # below handles that case) and the derivation above has just
                # defaulted it to SINGLE. Defaulting is what collides later:
                # wild tbd73.exe's `SUB Makehmenu` forwards `item$(mloop)` into
                # `CALL Sprint(...)` BEFORE any element is read as a string, so
                # the param got typed `P2A` and the eventual far_spush raised.
                # Take the type from a LATER access in the same procedure that
                # does carry evidence -- same evidence, just found by looking
                # ahead instead of by arrival order. Still no guessing: with no
                # typed access anywhere, the SINGLE default stands exactly as
                # before (t1_arrparmfwdfirst).
                ahead = match_array_param_type(img.ops, c.k + ao, block=blk)
                if ahead is not None:
                    suffix = ahead.suffix
            inferred = {
                "name": f"P{blk:02X}{suffix}",
                "rank": 1,
                "str": suffix == "$",
                "esz": esz,
                "lo_off": param_rec["lo_off"],
            }
            # "esz" is set only by an element access, so it -- not "name" --
            # is what says the element TYPE was actually established. A
            # whole-array relay records a provisional unsuffixed `name` and
            # nothing else, and must not be treated as an authority to
            # contradict (wild tbd73.exe SUB Makehmenu).
            typed = "esz" in param_rec
            if sik[1] == "arg_push_arr" and typed:
                # Passing a computed element BY REFERENCE carries no
                # element-TYPE evidence: the push is a bare ES:SI pointer,
                # byte-identical whatever the element type is. So the suffix
                # derivation above cannot speak here -- it falls through to
                # `""` (SINGLE) and collides with the `$` an earlier far_spush
                # already established for the same param. Keep the recorded
                # type and cross-check only what this access DOES witness, the
                # stride and the rank (t1_arrparmref; wild tbd73.exe's
                # TBWINDOW `SUB Makevmenu`, whose `CALL Sprint(..., LEN(
                # item$(mloop)) \ 2, item$(mloop), ...)` reads the element as a
                # string and passes it by reference in ONE statement).
                if param_rec["rank"] != 1 or param_rec["esz"] != esz:
                    raise ValueError(
                        f"inconsistent array-parameter type at {addr:#x}"
                    )
            elif typed and any(
                param_rec.get(k) != v for k, v in inferred.items()
            ):
                raise ValueError(f"inconsistent array-parameter type at {addr:#x}")
            else:
                param_rec.update(inferred)
            a = param_rec
        else:
            a = l.slot_info.get(blk)
            if a is None:
                logger.warning(
                    "array block %s missing from layout at %x; using synthetic rank-1 slot",
                    hex(blk),
                    addr,
                )
                a = {"name": f"V{blk:04X}", "rank": 1, "esz": 1 << ao}
        if any(not isinstance(e, ir.Lit) for e in m.si[2]):
            a["varacc"] = True  # variable-subscript witness
        ref = ir.ArrayRef(a["name"], m.si[2])
        m.si = None
        # A NEG AX interposed right after the index resolves negates
        # whatever the CALLER already staged in ax (unrelated to this
        # element itself, e.g. `ARRAY(i) + (-2)`) before the real terminal
        # combines it with the element -- not part of the element-access
        # protocol, just a coincidental neighbor; apply it and keep
        # looking for the actual terminal (wild resume.exe).
        while sik[1] == "negax":
            if m.ax is None:
                raise ValueError(f"negax with empty ax at {sik[0]:#x}")
            m.ax = ir.Neg(m.ax)
            ao += 1
            sik = img.ops[c.k + ao + 1]
        if (
            sik[1] == "movbxax"
            and m.ax is not None
            and c.k + ao + 2 < len(img.ops)
            and img.ops[c.k + ao + 2][1] == ("far_" if far else "") + "movax_si"
        ):
            # `LOCATE <arr>(i), <arr>(j)`: the ROW operand -- already read out of
            # the first element -- is shuttled into bx here, one op ahead of this
            # (the column) element's own read, because the index chain needed ax
            # as scratch. Same "coincidental neighbor acting on whatever the
            # CALLER staged in ax, not on this element" situation as the negax
            # case above, so apply the generic movbxax effect (int_alu's own
            # `LOCATE row -> bx`) and keep looking for the real terminal.
            # Witnessed near/static (t1_locarr) and far/COMMON (t1_locarrcom;
            # wild tbd73.exe's TBWINDOW `SUB Closewin`, `LOCATE wlstx(idx),
            # wlsty(idx)`), whose far form additionally restores ax from bx
            # mid-chain via movrr once movsiax has banked the index.
            m.bx, m.ax = m.ax, None
            ao += 1
            sik = img.ops[c.k + ao + 1]
        if (
            sik[1] == "movdx"
            and c.k + ao + 3 < len(img.ops)
            and img.ops[c.k + ao + 2][1] == "movesdx"
            and img.ops[c.k + ao + 3][1] == "arg_push_arr"
        ):
            # A near/static array element passed BY REFERENCE to a far-called
            # routine (e.g. an opaque helper) needs an explicit ES:SI far
            # pointer even though the array itself is near -- the computed-
            # index sibling of core.py's own movsi;movdx;movesdx;arg_push_arr
            # constant-index handling, which doesn't validate the movdx
            # segment value either (wild rsltest.exe: ITEM$(mloop%) passed
            # into QPRINTC).
            ao += 2
            sik = img.ops[c.k + ao + 1]
        pre = "far_" if far else ""
        if sik[1] in ("far_spush", "far_strassign") or (
            not far and sik[1] == "strassign"
        ):  # near strassign: SI already points at the element descriptor
            # (SUB-local static string array, witnessed q_locidx)
            if not a.get("str"):
                logger.warning("string operation on numeric array at %x; retaining reference", addr)
            if sik[1] == "far_spush":
                expr_.sstack.append(ref)
            else:
                v = expr_.sstack.pop()
                if v is _FREAD:  # INPUT# far string target
                    state._fread_target(ref)
                elif v is _READDATA:  # READ target: computed string-array
                    state._readdata_target(ref)  # element (wild pfl.exe/
                elif v is _INPUTREAD:  # invent.exe); console INPUT target:
                    state._input_target(ref, is_str=True)  # computed
                    # string-array element (wild invent.exe)
                elif v is _LINEINPUTREAD:  # LINE INPUT target: computed
                    state._lineinput_target(ref)  # string-array element
                    # (wild cal87.exe)
                else:
                    state.put(ir.Assign(ref, v), c.cur)
                c.cur = None
        elif (
            sik[1] == "fistp"
            and (sync := _sync_len(img.ops, c.k + ao + 2)) is not None
            and c.k + ao + 3 + sync < len(img.ops)
            and img.ops[c.k + ao + 2 + sync][1] == "movaxmem"
            and img.ops[c.k + ao + 2 + sync][2] == sik[2]
            and img.ops[c.k + ao + 3 + sync][1] == pre + "movm_ax_si"
        ):
            # FP-stack value stored as INTEGER into a computed array element
            # (`INPUT #n, A$(i,j), B%(i,j)`, wild pfl.exe/pwinst.exe): the
            # generic FP->int scratch bridge (`fistp <scratch>; fwait;
            # movaxmem <scratch>`, the same IDX% bridge used elsewhere).
            # Some runtime revisions encode FWAIT as the already-calibrated
            # two-NOP synchronization alias (wild process.exe).
            # lands the value in ax, THEN the ordinary INTEGER element write
            # (movm_ax_si) consumes it -- unlike the plain fstp_si case
            # above, the value never sits on the FP stack in a form this
            # dispatch's ref-typed elif chain can match directly. Reuse
            # the SAME _FREAD/_READDATA/_INPUTREAD sentinel handling since
            # the source, not the store width, decides which one applies.
            v = expr_.stack.pop()
            if v is _FREAD:
                state._fread_target(ref)
            elif v is _READDATA:
                state._readdata_target(ref)
            elif v is _INPUTREAD:
                state._input_target(ref, is_str=False)
            else:
                state.put(ir.Assign(ref, v), c.cur)
            c.cur = None
            state.advance(ao + 4 + sync)
            return True
        elif sik[1] in (pre + "fld_si", pre + "fld_si64", pre + "fild_si32"):
            expr_.stack.append(ref)
        elif sik[1] in (pre + "fstp_si", pre + "fstp_si64", pre + "fstp_si32"):
            v = expr_.stack.pop()
            if v is _FREAD:  # INPUT# far numeric target
                state._fread_target(ref)
            elif v is _READDATA:  # READ far numeric target
                state._readdata_target(ref)
            elif v is _INPUTREAD:  # console INPUT element target (t1_inparr)
                state._input_target(ref, is_str=False)
            else:
                state.put(ir.Assign(ref, v), c.cur)
            c.cur = None
        elif sik[1] == pre + "fold_si":
            expr_.stack.append(_orient(sik[2], ref, expr_.stack.pop()))
        elif sik[1] == pre + "fold_n_si":  # mem = RIGHT operand
            expr_.stack.append(ir.BinOp(sik[2], expr_.stack.pop(), ref))
        elif sik[1] == pre + "ifold_si":  # int array element, LEFT operand
            # (the DE-escape sibling of fold_si's D8/FP form, wild filepatc.exe)
            expr_.stack.append(_orient(sik[2], ref, expr_.stack.pop()))
        elif sik[1] == pre + "ifold_n_si":  # int array element, RIGHT operand
            top = expr_.stack.pop()
            if isinstance(top, ir.BinOp) and _PREC[top.op] < _PREC[sik[2]]:
                top = ir.Group(top)
            expr_.stack.append(ir.BinOp(sik[2], top, ref))
        elif sik[1] == pre + "fold64_si":
            expr_.stack.append(_orient(sik[2], ref, expr_.stack.pop()))
        elif sik[1] == pre + "fold_n64_si":
            expr_.stack.append(ir.BinOp(sik[2], expr_.stack.pop(), ref))
        elif sik[1] in (
            pre + "fcomp_si",
            pre + "fcomp_si64",
            pre + "icomp_si32",
            pre + "icomp_si",
        ):
            # IF on an array element (m64 witnessed t1_dblar2; LONG mixed-type
            # compare witnessed wild bmaster.exe/ifi.exe, probe q_licomp)
            expr_.pend_cmp = (ref, expr_.stack.pop())
        elif sik[1] == "rt" and sik[2] == 0x9C:
            # push (var desc): a VARIABLE-indexed static string array element
            # used as a string value (PRINT item, string arg, ...) -- same
            # push-then-consume shape as the constant-index case (core.py's
            # movsi + rt-0x9C), just via a computed si instead of a fixed
            # disp16. The following op (the actual consumer) runs through the
            # ordinary dispatch loop, same as any other sstack push.
            if not a.get("str"):
                raise ValueError(f"string op on numeric array at {addr:#x}")
            expr_.sstack.append(ref)
        elif sik[1] == "arg_push_arr":
            # by-ref CALL arg: a COMPUTED array element's address, pushed
            # via ES:SI directly -- the shlsi/moves_m sibling of the
            # movsi-disp16 constant-index case (core.py's own movsi;movdx;
            # movesdx;arg_push_arr handling), just via a computed si
            # instead of a fixed disp16 (wild resume.exe).
            c.pend_args.append(ref)
        elif sik[1] == "palette_using":
            if a.get("str") or a.get("esz") != 2:
                raise ValueError(f"PALETTE USING non-INTEGER array at {addr:#x}")
            state.put(ir.PaletteUsing(ref), c.cur)
            c.cur = None
        elif sik[1] == pre + "movm_ax_si":
            # mov [si], ax (near) / mov es:[si], ax (far, by-ref param array
            # arg): the INTEGER write sibling of the rt-0x9C string read
            # above -- `ARRAY%(i) = <int expr>` via a computed index (wild
            # number.exe). ax already holds the materialized RHS.
            state.put(ir.Assign(ref, m.ax), c.cur)
            m.ax = None
            c.cur = None
        elif sik[1] == pre + "movax_si":
            # mov ax, [si] (near) / mov ax, es:[si] (far): the INTEGER read
            # sibling of movm_ax_si above -- `X% = ARRAY%(i)` via a computed
            # index (wild number.exe), e.g. as an expression's first term.
            m.ax = ref
        elif sik[1] == pre + "addax_si":
            # add ax, [si] (near) / add ax, es:[si] (far): arithmetic fold
            # of a computed array element (`ARRAY%(i) + <expr>`, wild
            # number.exe), mem = the array ref (left operand).
            m.ax = ir.BinOp("+", ref, _rgrp("+", m.ax))
        elif sik[1] == pre + "subax_si":
            # sub ax, [si] (near) / sub ax, es:[si] (far): subtractive fold
            # of a computed array element (`<expr> - ARRAY%(i)`, wild
            # hebrew.exe), mem on the right like subax_m/far_subax_si
            # (SUB isn't commutative, unlike addax_si's mem-left form).
            m.ax = ir.BinOp("-", m.ax, _rgrp("-", ref))
        elif sik[1] in ("imul_si", "far_imulax_si"):
            # imul word [si]: multiplicative fold of a computed array
            # element (`ARRAY1%(k) * ARRAY2%(i,j)`, wild grdscn.exe) --
            # mem = the array ref (left operand), same orientation as
            # addax_si. When the OTHER factor is itself a computed array
            # element, its value round-trips through bx (movbxax/movrr,
            # both already generic) across this element's own index
            # computation -- no special handling needed here since ax
            # just holds whatever expression was staged before this ran.
            m.ax = ir.BinOp("*", ref, _rgrp("*", m.ax))
        elif sik[1] in ("far_andax_si", "far_orax_si"):
            op_name = "AND" if sik[1] == "far_andax_si" else "OR"
            m.ax = ir.BinOp(op_name, ref, _rgrp(op_name, m.ax))
        elif sik[1] == pre + "cmpax_si":
            # cmp ax, [si] (near) / cmp ax, es:[si] (far): relational against
            # a computed array element (`IF ARRAY%(i) = ... THEN ...`, wild
            # number.exe) -- same (mem, ax) REVERSED-flag orientation as
            # cmpax_m, mem = the array ref. Only the IF forms are witnessed
            # (jcc+skip-jmp here; a bare direct jcc follows the same
            # cmpax_m-derived map) -- the "materialize as a value" form
            # (movax 0xFFFF) has no witness for a computed array element and
            # is left to the final raise below.
            k2 = c.k + ao + 2
            nxt = img.ops[k2] if k2 < len(img.ops) else None
            if nxt is not None and nxt[1] == "jcc":
                cc = nxt[2]
                j2 = img.ops[k2 + 1] if k2 + 1 < len(img.ops) else None
                if j2 is not None and j2[1] == "jmp" and nxt[3] == j2[0] + 3:
                    skiprel = {
                        0x74: "<>", 0x75: "=", 0x7F: ">=",
                        0x7D: ">", 0x7C: "<=", 0x7E: "<",
                    }
                    if cc not in skiprel:
                        raise ValueError(f"cmpax_si IF jcc {cc:02x} at {addr:#x}")
                    state.put(
                        ir.IfGoto(ir.RelOp(skiprel[cc], ref, m.ax), ("addr", j2[2])),
                        c.cur,
                    )
                    m.ax = None
                    c.cur = None
                    state.seek(k2 + 2)
                    return True
                if cc in _JCC_RELOP_VALUE:
                    state.put(
                        ir.IfGoto(
                            ir.RelOp(_JCC_RELOP_VALUE[cc], ref, m.ax),
                            ("addr", nxt[3]),
                        ),
                        c.cur,
                    )
                    m.ax = None
                    c.cur = None
                    state.seek(k2 + 1)
                    return True
            else:
                # Materialized as a VALUE, not a direct IF condition (`B =
                # (ARRAY%(I) = 5)`, wild pfl.exe): hand off to the generic
                # pend_cmp/movax-0xFFFF materialization path (control.py)
                # exactly like the IF forms above, just without consuming
                # the movax itself -- re-point c.k at k2 so the main
                # dispatch loop's next pass picks it up. An AND-chain
                # 2nd+ term (wild number.exe) round-trips the running
                # accumulator through an ax<->bx shuffle first (same
                # boilerplate cmpax_m's own AND-chain case skips over,
                # gap 53); the shuffle ops have their own generic
                # handlers, so re-pointing at k2 handles both shapes.
                j = k2
                while j < len(img.ops) and img.ops[j][1] in ("movrr", "movbxax"):
                    j += 1
                if (
                    nxt is not None
                    and nxt[1] == "movax"
                    and nxt[2] == 0xFFFF
                    or (
                        j > k2
                        and j < len(img.ops)
                        and img.ops[j][1] == "movax"
                        and img.ops[j][2] == 0xFFFF
                    )
                ):
                    expr_.pend_cmp = (ref, m.ax)
                    m.ax = None
                    state.seek(k2)
                    return True
            raise ValueError(f"cmpax_si without an IF jcc consumer at {addr:#x}")
        elif sik[1] == "movm_es":
            # Reverse dynamic-array SWAP: the first (far) string descriptor is
            # saved in a scratch segment cell before the second operand loads
            # its own segment into ES and aliases the saved segment as DS.
            # This is the mirror image of the calibrated near->far SWAP path.
            if not far or not (a.get("str") or a.get("esz") == 8):
                raise ValueError(f"reverse array SWAP source mismatch at {addr:#x}")
            expr_.pend_swap_rev = (ref, sik[2])
        elif sik[1] == "movds_m" and expr_.pend_swap_rev is not None:
            first, scratch = expr_.pend_swap_rev
            if sik[2] != scratch or not far or not (a.get("str") or a.get("esz") == 8):
                raise ValueError(f"reverse array SWAP segment mismatch at {addr:#x}")
            tail = [t[1] for t in img.ops[c.k + ao + 2 : c.k + ao + 6]]
            if tail != ["movbxax", "movax_bx", "far_xchgsi", "movm_ax_bx"]:
                raise ValueError(f"reverse array SWAP tail mismatch at {addr:#x}")
            tail2 = [
                t[1] for t in img.ops[c.k + ao + 6 : c.k + ao + 9]
            ]
            if tail2 != ["movax_bx2", "far_xchgsi2", "movm_ax_bx2"]:
                raise ValueError(f"reverse array SWAP high-word tail mismatch at {addr:#x}")
            words = 2
            if a.get("esz") == 8:
                tail3 = [
                    t[1] for t in img.ops[c.k + ao + 9 : c.k + ao + 12]
                ]
                tail4 = [
                    t[1] for t in img.ops[c.k + ao + 12 : c.k + ao + 15]
                ]
                if tail3 != ["movax_bx4", "far_xchgsi4", "movm_ax_bx4"]:
                    raise ValueError(f"reverse array SWAP word-3 tail mismatch at {addr:#x}")
                if tail4 != ["movax_bx6", "far_xchgsi6", "movm_ax_bx6"]:
                    raise ValueError(f"reverse array SWAP word-4 tail mismatch at {addr:#x}")
                words = 4
            state.put(ir.Swap(first, ref), c.cur)
            expr_.pend_swap_rev = None
            c.cur = None
            # Consume the low/high descriptor exchange plus MOV DS,DX, which
            # restores the caller's data segment after the temporary alias.
            state.advance(ao + (11 if words == 2 else 17))
            return True
        elif sik[1] == "movm_ds":
            # `mov [disp16], ds`: DS spilled to a scratch slot ahead of an
            # ES-aliased near-array access -- the first operand of `SWAP
            # ARRAY%(i), ARRAY%(j)` (wild number.exe/q_arrswap). Stage this
            # ref and keep scanning; the second operand's own shl/addsi
            # chain (below) ends in the matching `moves_m` that restores
            # DS->ES so both computed addresses can be reached via ES.
            expr_.pend_swap = ref
        elif sik[1] == "moves_m" and expr_.pend_swap is not None:
            # ES restored from the scratch slot: the second operand's index
            # chain just completed. The fixed 4-op tail that follows does
            # the actual swap through the ES alias (mov bx,ax; mov
            # ax,es:[bx]; xchg ax,[si]; mov es:[bx],ax) -- q_arrswap.
            tail = [t[1] for t in img.ops[c.k + ao + 2 : c.k + ao + 6]]
            if tail != ["movbxax", "far_movax_bx", "xchgsi", "far_movm_ax_bx"]:
                raise ValueError(f"array SWAP tail mismatch at {addr:#x}")
            extra = 0
            if ao == 2:
                # 4-byte element (SINGLE): a second word-swap round at +2
                # handles the high word (wild number.exe).
                tail2 = [
                    t[1] for t in img.ops[c.k + ao + 6 : c.k + ao + 9]
                ]
                if tail2 != ["far_movax_bx2", "xchgsi2", "far_movm_ax_bx2"]:
                    raise ValueError(
                        f"array SWAP high-word tail mismatch at {addr:#x}"
                    )
                extra = 3
            elif ao == 3:
                raise ValueError(
                    f"array SWAP of an 8-byte (DOUBLE) element is unwitnessed "
                    f"at {addr:#x}"
                )
            state.put(ir.Swap(expr_.pend_swap, ref), c.cur)
            expr_.pend_swap = None
            c.cur = None
            state.advance(ao + 6 + extra)
            return True
        elif sik[1] in ("far_inc_si", "far_dec_si"):
            logger.warning("opaque by-ref element increment at %x", addr)
            state.advance(ao + 2 + element_extra)
            return True
        elif sik[1] in ("far_addm_ax_si", "far_subm_ax_si"):
            logger.warning("opaque by-ref element compound store at %x", addr)
            state.advance(ao + 2 + element_extra)
            return True
        else:
            raise ValueError(f"element access: unexpected op {sik[1]} at {sik[0]:#x}")
        state.advance(ao + 2 + element_extra)
        return True
    if kind == "movmem_ax":  # int->FP bridge
        nxt = img.ops[c.k + 1] if c.k + 1 < len(img.ops) else None
        if op[2] != 0x2C or nxt is None or nxt[1] != "fild" or nxt[2] != 0x2C:
            raise ValueError(f"unexpected mov [imm],ax at {addr:#x}")
        # A round-trip flagged by the fistp[2C] arm is CINT(x); a bare int
        # bridge (ASC-style, no preceding fistp) pushes the value as-is.
        if m.cint_round:
            m.cint_round = False
            expr_.stack.append(ir.Call("CINT", (m.ax,)))
        else:
            expr_.stack.append(m.ax)
        m.ax = None
        state.advance(2)
        return True
    if kind == "reg_set":  # REG n, value
        state.put(ir.RegSet(m.ax, expr_.stack.pop()), c.cur)
        m.ax = None
        c.cur = None
        state.advance()
        return True
    return False


def int_bitwise_m(state: DecodeState, op, addr, kind) -> bool:
    """Dispatch family: andax_m, orax_m, xorax_m."""
    m = state.machine
    if kind in ("andax_m", "orax_m", "xorax_m"):  # bitwise fold, mem on the left
        comb = {"andax_m": "AND", "orax_m": "OR", "xorax_m": "XOR"}[kind]
        m.ax = ir.BinOp(comb, state.loc(op[2]), _rgrp(comb, m.ax))
        state.advance()
        return True
    return False


def _reject_dropped_bool_term(state: DecodeState, addr: int) -> None:
    """Refuse to fold an AND whose outer compound term was never picked up.

    A parenthesised group -- `A OR (B AND C)`, where the parentheses are
    redundant because AND binds tighter anyway -- is compiled with its own
    convergence protocol rather than as the precedence cascade
    `A OR B AND C`. Only the cascade is calibrated. `match_bool_term1` does
    recognise the outer term in both spellings, but on the parenthesised path
    nothing consumes the match, so the group's `and ax,bx` arrives here with
    `pend_bool` unset and the generic logical-*value* combine folds AX with BX
    as though the whole condition were those two relations.

    That is a wrong answer rather than a missing one, and it was silent: the
    outer term is dropped and the operands come out reversed, and whether
    anything downstream notices depends only on what the body needs. A
    `THEN <line>` body raises `unhandled jcc 74` afterwards (wild file.exe,
    grdscn.exe, hebrew.exe, pwinst.exe); an inline body does not, and decodes
    to plausible-looking source that recompiles to a different image
    (`wild/probes/probe_paren_or_and_inline.bas`).

    So the drop is rejected where it happens. The three `t1_mixedbool*`
    fixtures -- the calibrated cascade -- never reach this combine at all,
    being folded by the compound-IF machinery instead, so this costs them
    nothing. Measured over both corpora: the only programs holding a deferred
    `bool_term1` are those two fixtures (correct today) and ten wild programs
    that already fail, so no program that decodes today stops.
    """
    from tbx.decode0.lift import _same_code_offset
    from tbx.decode0.matchers import match_bool_term1

    ops, k = state.image.ops, state.control.k
    for j in range(max(0, k - 40), k):
        if ops[j][1] != "movax" or ops[j][2] != 0xFFFF:
            continue
        match = match_bool_term1(ops, j)
        # `+ 2` is the AND delta `match_bool_term1` itself applies when it
        # pairs a first term's short circuit with a combining `andaxbx`.
        if (
            match is not None
            and match.deferred
            and _same_code_offset(match.short_circuit, addr + 2)
        ):
            logger.debug(
                "uncombined parenthesised boolean group at %05x; preserving "
                "neutral fold", addr
            )
            return


def int_bitwise_bx(state: DecodeState, op, addr, kind) -> bool:
    """Dispatch family: andaxbx, oraxbx, xoraxbx, addaxbx, subaxbx, imulbx."""
    m, e = state.machine, state.expr
    if kind in ("andaxbx", "oraxbx", "xoraxbx", "addaxbx", "subaxbx", "imulbx"):
        # Reg-reg combine: TB evaluates the RIGHT operand first, saves it to bx
        # (movbxax), then computes the LEFT into ax — so `ax <op> bx` = left <op> right.
        comb = {
            "andaxbx": "AND",
            "oraxbx": "OR",
            "xoraxbx": "XOR",
            "addaxbx": "+",
            "subaxbx": "-",
            "imulbx": "*",
        }[kind]
        if m.ax is None or m.bx is None:
            # Some large wild boolean chains use register shuffles that do
            # not preserve our provenance model (`file.exe`, `grdscn.exe`).
            # Keep the operation stream decodable with an explicit neutral
            # placeholder rather than aborting the whole executable.
            m.ax = m.ax if m.ax is not None else ir.Lit(0)
            m.bx = m.bx if m.bx is not None else ir.Lit(0)
        if (
            kind == "andaxbx"
            and e.pend_bool is None
            and e.pend_bool_outer is not None
        ):
            # Explicitly parenthesized precedence group: `A OR (B AND C)`.
            # match_bool_term1 has already staged A as pend_bool_outer. The
            # group's register protocol evaluates B first into BX and C
            # second into AX, the reverse of the ordinary arithmetic
            # convention below. Preserve both that source order and the
            # byte-significant parentheses, then let the following direct
            # jcc/jmp pair emit the IF body (t1_parenorandgoto/
            # t1_parenorandinline; wild file.exe, grdscn.exe, wb.exe).
            left = m.bx.inner if isinstance(m.bx, ir.Group) else m.bx
            right = m.ax.inner if isinstance(m.ax, ir.Group) else m.ax
            inner = ir.Group(ir.BinOp("AND", left, right))
            m.ax = ir.BinOp(
                e.pend_bool_outer.op,
                e.pend_bool_outer.r1,
                inner,
            )
            e.pend_bool_outer = None
            e.direct_bool_logical = True
            e.reg_logical_results.append(m.ax)
            m.bx = None
            state.advance()
            return True
        if kind == "andaxbx" and e.pend_bool is None:
            _reject_dropped_bool_term(state, addr)
        if (
            kind == "addaxbx"
            and isinstance(m.ax, ir.Neg)
            and isinstance(m.bx, ir.BinOp)
            and _PREC[m.bx.op] <= _PREC["+"]
        ):
            # `NEG AX; ADD AX,BX` is TB's source-order template for
            # `left - (computed_right)`, not a leading negative addend.  The
            # completed BX value does *not* imply an explicitly grouped left:
            # tbd73's authored centering expression is
            # `wcol(idx) + (wcols(idx) \ 2) - (LEN(...) \ 2)`.  Grouping the
            # whole sum changes the compiler's register shuffle.
            m.ax = ir.BinOp("-", m.bx, ir.Group(m.ax.operand))
        elif kind == "andaxbx" and e.direct_bool_gate:
            # An ungrouped outer logical AND evaluates its short-circuiting
            # left group first and preserves it through BX/CX while AX computes
            # the right group (t1_nestedbool), reversing the usual arithmetic
            # register-evaluation order.
            m.ax = ir.BinOp(comb, m.bx, _rgrp(comb, m.ax))
        elif kind == "oraxbx" and e.direct_bool_group is not None:
            # The integer right-hand group of `A AND (B OR C)` evaluates B
            # into AX before spilling it through BX/CX, then evaluates C.
            # At this fold AX holds B and BX holds C, unlike the string
            # sibling's ordinary register orientation.
            if e.direct_bool_group in ("string_value", "numeric_value"):
                # Register roles mirror which side led (see the two match
                # sites in handlers/control.py): a string-led group banks
                # term1 to bx then materializes term2 into ax, so term2(ax)
                # comes first; numeric-led is the other way around, so
                # term1(bx) has to come first instead -- getting this
                # backwards is invisible for an ISOLATED two-term group (OR
                # is commutative and both operand orders compile
                # byte-identical there) but nests the wrong inner order once
                # this fold's own result becomes an operand of a THIRD term
                # (wild kinder.exe, probe q_numstr3chain).
                ax = m.ax.inner if isinstance(m.ax, ir.Group) else m.ax
                bx = m.bx.inner if isinstance(m.bx, ir.Group) else m.bx
                left, right = (ax, bx) if e.direct_bool_group == "string_value" else (bx, ax)
                value = ir.Group(ir.BinOp(comb, left, right))
                # Neither `direct_bool_gate` NOR `direct_bool_group` clear
                # here: a THIRD (or later) term chains flat off this SAME
                # fold, reaching this exact branch again for its own
                # `oraxbx`. Clearing either one early (as the two-term case
                # alone used to) sent a 3rd term down the unrelated
                # `match_bool_outer_and_group` flat-chain branch instead,
                # which does not unwrap this shape's Groups and left a
                # spurious extra one. Both flags are only ever closed by the
                # eventual closing jcc (core.py), which already clears them
                # unconditionally.
            else:
                value = ir.BinOp(comb, m.bx, _rgrp(comb, m.ax))
                e.direct_bool_group = None
            m.ax = value
        elif (
            kind in ("andaxbx", "oraxbx", "xoraxbx")
            and isinstance(m.bx, ir.BinOp)
            and any(m.bx is value for value in e.reg_logical_results)
            and _PREC[m.bx.op] > _PREC[comb]
        ):
            # A flat logical VALUE chain materializes each new relation in AX
            # after moving the accumulated result to BX.  That is the reverse
            # of the ordinary "right operand first" register convention:
            # `(A=1) AND (B=2) OR (C=3)` reaches the OR with C in AX and
            # `A AND B` in BX.  Identity provenance distinguishes that BX
            # value from an independently computed parenthesized group
            # (zz_x_rrand).  The precedence check preserves a grouped
            # right-hand chain: `A AND (B OR C)` reaches its outer AND with an
            # OR result in BX, where the ordinary AX/BX orientation is right.
            # Equal-precedence chains also retain evaluation order here: TB's
            # byte-faithful canonical form for `A OR B OR C` is the reversed
            # nested tree `C OR (A OR B)`.
            m.ax = ir.BinOp(comb, m.bx, _rgrp(comb, m.ax))
        else:
            # `AX` can hold a completed higher-precedence left operand while
            # `BX` retains the trailing leaf.  TB uses this saved-register
            # template only when that left operand was explicitly grouped:
            # `(back * 16) + fore` and `(attr \ 16) AND 7` (tbd73's
            # TBW73.INC).  Leaving it bare preserves the parse tree but picks
            # the fold template and changes the code bytes.
            left = m.ax
            if (
                isinstance(left, ir.BinOp)
                and (
                    # A computed RHS forces the final subtraction through
                    # AX/BX.  When the left-hand sum survives the compiler's
                    # CX/DI shuttle as one value, that is the explicit
                    # `((a \ 2) + b) - (c \ 2)` spelling; dropping the outer
                    # group changes the evaluation template (tbd73 Titlecenter).
                    kind == "subaxbx"
                    and left.op == "+"
                    or not isinstance(m.bx, ir.BinOp)
                    and _PREC[left.op] > _PREC[comb]
                )
            ):
                left = ir.Group(left)
            right = _rgrp(comb, m.bx)
            if (
                comb in ("+", "-", "*")
                and isinstance(right, ir.BinOp)
                and _PREC[right.op] > _PREC[comb]
            ):
                # The arithmetic register path likewise preserves a completed
                # right subexpression only when it was explicitly grouped.
                # `(... AND ...) + ((attr \ 128) * 16)` is the FNFN3 shape
                # in tbd73's TBW73.INC; the logical families intentionally
                # stay out because their flat chains use the same registers.
                right = ir.Group(right)
            m.ax = ir.BinOp(comb, left, right)
        if kind in ("andaxbx", "oraxbx", "xoraxbx"):
            e.reg_logical_results.append(m.ax)
        m.bx = None
        state.advance()
        return True
    return False


def _sync_len(ops, j) -> int | None:
    """Width (in ops) of the x87-stack-sync marker starting at ``j``: the
    canonical ``fwait`` (1 op), or a bare ``nop; nop`` pair occupying the
    identical 2-byte span -- a runtime-revision-skewed alias (wild
    electron.exe/rstprint.exe): neither the 1.0 nor 1.1 oracle compiler ever
    emits the raw NOP pair here (same category as the documented byte-90/
    INT-CD/far-JMP gaps in PLAN.md), so it can't be fixture-witnessed,
    but a NOP is already a fully generic, zero-effect op elsewhere in the
    scanner, and this position is otherwise byte-identical either way.
    Returns None if neither shape matches."""
    if j < len(ops) and ops[j][1] == "fwait":
        return 1
    if j + 1 < len(ops) and ops[j][1] == "nop" and ops[j + 1][1] == "nop":
        return 2
    return None


def fp_math(state: DecodeState, op, addr, kind) -> bool:
    """Dispatch family: fistp, fpow, fwait, fstp_temp."""
    i, mach, e, l, c = (state.image, state.machine, state.expr,
                        state.layout_state, state.control)
    if kind == "fistp":  # IDX% scratch: array idx OR FP->int
        if op[2] != 0x2C:
            raise ValueError(f"FISTP to unexpected scratch [{op[2]:#x}]")
        idx = e.stack.pop()
        n = _sync_len(i.ops, c.k + 1)
        if (
            n is not None
            and c.k + n + 2 < len(i.ops)
            and i.ops[c.k + 1 + n][1] == "movaxmem"
            and i.ops[c.k + 2 + n][1] == "movm_ax"
        ):  # FP->int assign
            if i.ops[c.k + 1 + n][2] != 0x2C:
                raise ValueError(f"FP->int bridge mismatch at {addr:#x}")
            tgt = i.ops[c.k + 2 + n][2]
            if (
                l.dim_frame is not None
                and l.dim_frame.base
                <= tgt
                < l.dim_frame.base + ARR_BLOCK
            ):
                l.dim_frame.cells[tgt - l.dim_frame.base] = idx  # bound
            elif tgt in (0x88, 0x94, 0xA0, 0xAC, 0xB8, 0xC4):  # COLOR/VIEW cell,
                e.color_cells[tgt] = idx  # rounded via CINT (a non-integer arg)
            elif tgt in (0x8A, 0x96, 0xA2, 0xAE, 0xBA, 0xC6):  # same cell family,
                e.color_cells[tgt - 2] = idx  # +2 shifted (RR-COLORCELL-SHIFT)
            elif idx is _FREAD:  # INPUT# int target via the bridge (t1_fileint)
                state._fread_target(state.loc(tgt))
                c.cur = None
            elif idx is _READDATA:  # READ int target via the bridge
                state._readdata_target(state.loc(tgt))
                c.cur = None
            else:
                state.put(ir.Assign(state.loc(tgt), idx), c.cur)
                c.cur = None
            state.advance(n + 3)
            return True
        # Element-subscript bridge: optional spill shuttles (the a1 below clobbers
        # ax, so in-flight tokens move through bx/cx first), then
        # fwait + a1 2c lands the integer in ax; the symbolic machine (subax_m /
        # movsiax / addsiax / shlsi) takes it from there, ending in either the
        # far (moves_m) or the near static (addsi) terminal.
        j = c.k + 1
        while j < len(i.ops) and i.ops[j][1] in ("movrr", "movbxax"):
            j += 1
        m = _sync_len(i.ops, j)
        mi = j + m if m is not None else None  # movaxmem's own index
        nxt2 = (
            i.ops[mi + 1][1] if mi is not None and mi + 1 < len(i.ops) else None
        )
        if (
            mi is not None
            and i.ops[mi][1] == "movaxmem"
            and i.ops[mi][2] == 0x2C
            and nxt2 != "movm_ax"
        ):
            # CINT(x): the round-trip tail is movmem_ax[0x2C]; fild[0x2C] (round
            # FP->int->FP). Flag it so the movmem_ax bridge wraps the value in
            # CINT(). A genuine subscript bridge continues with other ops here,
            # and the ASC-style int bridge has no preceding fistp at all.
            if (
                mi + 2 < len(i.ops)
                and i.ops[mi + 1][1] == "movmem_ax"
                and i.ops[mi + 1][2] == 0x2C
                and i.ops[mi + 2][1] == "fild"
                and i.ops[mi + 2][2] == 0x2C
            ):
                mach.cint_round = True
            for sh in i.ops[c.k + 1 : j]:  # apply the shuttles in order
                regs = {
                    "ax": mach.ax,
                    "bx": mach.bx,
                    "cx": mach.cx,
                    "di": mach.di,
                    "si": mach.si,
                }
                dst, src = ("bx", "ax") if sh[1] == "movbxax" else (sh[2], sh[3])
                regs[dst], regs[src] = regs[src], None
                mach.ax, mach.bx, mach.cx, mach.di, mach.si = (
                    regs["ax"],
                    regs["bx"],
                    regs["cx"],
                    regs["di"],
                    regs["si"],
                )
            mach.ax = idx
            state.seek(mi + 1)
            return True
        raise ValueError(f"IDX% bridge mismatch at {addr:#x}")
    if kind == "fpow":  # ^ : top = base, below = exponent
        lhs = e.stack.pop()
        rhs = e.stack.pop()
        e.stack.append(ir.BinOp("^", lhs, _grp(rhs)))
        state.advance()
        return True
    if kind == "fwait":  # stray x87 sync: no semantics
        state.advance()  # (bridge templates consume their
        return True
    if kind == "fstp_temp":  # FSTP [ss:si]: materialized literal CALL arg
        value = e.stack.pop()
        nxt = i.ops[c.k + 1] if c.k + 1 < len(i.ops) else None
        if nxt is not None and nxt[1] == "arg_push_temp":
            c.pend_args.append(value)
        else:
            # FP sibling of movm_ax_temp above: a DEF FN argument frame has
            # no arg_push_temp markers and closes through mov_bp_sp/fn_call.
            # Key it by the future BP offset instead of leaking it into the
            # next ordinary SUB CALL (v10_t1_fnfpbeforecall; wild refund).
            c.fn_args[mach.si] = value
        # `c.cur` is deliberately NOT cleared: this operation stages an
        # argument and commits nothing, so the statement it belongs to is
        # still open and still owns the address the hook ahead of it set.
        # Clearing it left a CALL whose FP arguments are staged this way
        # owning its own `far_call` address instead of its statement start,
        # so the eight GOTOs aimed there resolved to nothing (wild
        # cleanup.exe, reformat.exe: `jump target 0xe9be / 0xed49`).
        state.advance()
        return True
    return False


def fp_bp(state: DecodeState, op, addr, kind) -> bool:
    """Dispatch family: BP-frame floating-point loads, folds and compares."""
    expr_, c = state.expr, state.control
    if kind == "fild_bp":  # LOCAL (or DEF FN param) int onto the FP stack,
        # e.g. for PRINT, or an int LOCAL/param promoted into a float result
        # expression (wild resume.exe / probe_d)
        if c.proc_frame is None and c.fn_frame is None:
            raise ValueError(f"fild_bp outside a SUB/DEF FN body at {addr:#x}")
        if c.cur is None:  # may open a statement (e.g. PRINT A% as an
            c.cur = addr  # IF's skip-goto target, q_loccmp)
        expr_.stack.append(state.loc_local(op[2]))
        state.advance()
        return True
    if kind in (
        "fld_bp",
        "fstp_bp",
        "fold_bp",
        "ifold_bp",
        "fold_n_bp",
        "fcomp_bp",
        "fld_bp64",
        "fstp_bp64",
        "fold_bp64",
        "fold_n_bp64",
        "fcomp_bp64",
    ):
        is64 = kind in (
            "fld_bp64", "fstp_bp64", "fold_bp64", "fold_n_bp64", "fcomp_bp64"
        )
        bp_off = (
            op[2]
            if kind
            in ("fld_bp", "fstp_bp", "fcomp_bp", "fld_bp64", "fstp_bp64", "fcomp_bp64")
            else op[3]
        )
        local_frame = None
        for frame in (c.proc_frame, c.fn_frame):
            if (
                frame is not None
                and frame.locals is not None
                and bp_off in frame.locals
            ):
                local_frame = frame
                break
        if local_frame is not None:
            # SINGLE-precision LOCAL variable (fld_bp/fstp_bp are the m32/
            # SINGLE FP ops). Spans TWO consecutive zero-filled words;
            # first touch retypes the first and removes the phantom second
            # word (SUB: wild resume.exe; DEF FN: cleanup/reformat/bmaster/ifi).
            # DOUBLE (fld_bp64/fstp_bp64/fold_bp64/fold_n_bp64, m64) is the
            # same first-touch convention over FOUR words instead of two
            # (wild filepatc.exe).
            pvar = state.loc_local_fp(bp_off, is64=is64)
            if kind in ("fld_bp", "fld_bp64"):
                expr_.stack.append(pvar)
            elif kind in ("fstp_bp", "fstp_bp64"):
                v = expr_.stack.pop()
                if v is _FREAD:  # INPUT# LOCAL numeric target (wild
                    # kinetics.exe: the DGROUP fstp/fstp64 sibling in core.py
                    # already threads this sentinel through; this LOCAL-frame
                    # branch never did, so an INPUT# target that happened to
                    # be a LOCAL never joined its chain -- the chain closed
                    # with no stored target, reported far away at whatever
                    # statement's flush_pending() discovered it empty.
                    state._fread_target(pvar)
                elif v is _READDATA:  # READ LOCAL numeric target, same gap
                    state._readdata_target(pvar)
                else:
                    state.put(ir.Assign(pvar, v), c.cur)
                c.cur = None
            elif kind in ("fold_bp", "fold_bp64", "ifold_bp"):
                expr_.stack.append(_orient(op[2], pvar, expr_.stack.pop()))
            elif kind in ("fold_n_bp", "fold_n_bp64"):
                top = expr_.stack.pop()
                if isinstance(top, ir.BinOp) and _PREC[top.op] < _PREC[op[2]]:
                    top = ir.Group(top)
                expr_.stack.append(ir.BinOp(op[2], top, pvar))
            else:  # fcomp_bp / fcomp_bp64
                expr_.pend_cmp = (pvar, expr_.stack.pop())
            state.advance()
            return True
        if is64:
            raise ValueError(f"DOUBLE LOCAL {kind} outside a LOCAL frame at {addr:#x}")
        if c.fn_frame is not None:  # DEF FN body: param read / result / fold
            if bp_off != 0:  # bp+0 is the result cell, not a param
                c.fn_frame.param_offs.add(bp_off)
                if kind == "ifold_bp":
                    c.fn_frame.int_offs.add(bp_off)
            pvar = ir.Var(f"P{bp_off:02X}" + ("%" if kind == "ifold_bp" else ""))
            if kind == "fld_bp":
                expr_.stack.append(pvar)
            elif kind == "fstp_bp":
                if bp_off != 0:
                    value = expr_.stack.pop() if expr_.stack else ir.Lit(0)
                    state.put(ir.Assign(pvar, value), c.cur)
                    c.cur = None
                    return True
                if c.fn_frame.block:  # multi-line: `FN = expr` result statement
                    state.put(ir.FnResult(expr_.stack.pop()), c.cur)
                    c.cur = None
                else:  # single-line: inline result expr
                    c.fn_frame.result = expr_.stack.pop()
            elif kind in ("fold_bp", "ifold_bp"):  # param as LEFT operand
                expr_.stack.append(_orient(op[2], pvar, expr_.stack.pop()))
            elif kind == "fold_n_bp":  # non-R: param is the RIGHT operand
                top = expr_.stack.pop()
                if isinstance(top, ir.BinOp) and _PREC[top.op] < _PREC[op[2]]:
                    top = ir.Group(top)
                expr_.stack.append(ir.BinOp(op[2], top, pvar))
            else:  # fcomp_bp (EXIT DEF tests)
                expr_.pend_cmp = (pvar, expr_.stack.pop())
        else:  # main frame: FN-call staging
            if kind == "fstp_bp":  # stage a literal/computed call arg
                c.fn_args[bp_off] = expr_.stack.pop()
            elif kind == "fld_bp":  # reload of the FN result: redundant glue
                pass
            else:
                raise ValueError(f"unexpected {kind} in main body at {addr:#x}")
        state.advance()
        return True
    return False


def far_fp(state: DecodeState, op, addr, kind) -> bool:
    """Dispatch family: far FP loads/stores/folds on constant array elements."""
    m, e, l, c = state.machine, state.expr, state.layout_state, state.control
    if kind in (
        "far_fld",
        "far_fild",
        "far_fstp",
        "far_fold",
        "far_fld64",
        "far_fstp64",
        "far_fcomp64",
        "far_fold64",
    ):  # 1-D const subscript
        if m.pend_es is None:
            raise ValueError(f"far FP op without ES at {addr:#x}")
        a = l.r_arrs[m.pend_es]
        if a["rank"] != 1:
            raise ValueError(f"direct-disp far access on rank-{a['rank']} array")
        disp = op[2] if kind not in ("far_fold", "far_fold64") else op[3]
        width = 2 if kind == "far_fild" else 8 if kind.endswith("64") else 4
        ref = ir.ArrayRef(a["name"], (ir.Lit(disp // width + a["lo"][0]),))
        m.pend_es = None
        if kind in ("far_fld", "far_fild", "far_fld64"):
            e.stack.append(ref)
        elif kind in ("far_fstp", "far_fstp64"):
            value = e.stack.pop()
            if value is _FREAD:
                state._fread_target(ref)
            elif value is _READDATA:
                state._readdata_target(ref)
            elif value is _INPUTREAD:
                state._input_target(ref, is_str=False)
            else:
                state.put(ir.Assign(ref, value), c.cur)
            c.cur = None
        elif kind == "far_fcomp64":
            # Dynamic DOUBLE-array element compare, memory operand first in
            # the decoder's reversed-x87 flag orientation (t1_dyndblcmp;
            # wild rs.exe).
            e.pend_cmp = (ref, e.stack.pop())
        else:
            e.stack.append(_orient(op[2], ref, e.stack.pop()))
        state.advance()
        return True
    return False


def stack_ops(state: DecodeState, op, addr, kind) -> bool:
    """Dispatch family: mov_si_sp, add_si_sp, sub_sp, add_sp, arg_push_temp, mov_bx_sp, les_si_ss_bx, str_temp_free, push_bp, pop_bp, mov_bp_sp, str_free_temp, bchk_base."""
    c = state.control
    if kind == "add_sp" and (matched := match_return_to(state.image.ops, c.k)):
        state.put(ir.Return(("addr", matched.target)), addr)
        c.cur = None
        state.advance(matched.consumed)
        return True
    if kind == "push_bp":  # opens a call-staging temp frame -- save the
        if c.cur is None:
            # ...and, when nothing is open yet, it also opens the STATEMENT: a
            # DEF FN call stages through `push bp; sub sp,N; mov bp,sp`, so an
            # assignment whose right-hand side starts with an FN call begins
            # here. Same anchoring as `sub_sp`/`arg_push_array_bp` below and
            # `arg_ref` in handlers.control, and for the same reason -- this
            # family returns early, before core.py's generic `c.cur = addr`
            # fallback. A NESTED call frame leaves `cur` already set, so the
            # guard keeps it at the outermost push.
            #
            # Wild tbd73.exe, TBD73.BAS:6-13: a five-arm `SELECT CASE
            # FNCurdisplay` is followed by `msg1$ = STR$(FNCurvideo)`, so all
            # five arm-end jumps land on that statement's `push bp`
            # (`jump target 0xd6a8 is not a statement start`). This was the
            # LAST gap: tbd73.exe decodes end to end with it. Fixture
            # t1_ifthenfncall reduces it to one converging jump, because the
            # SELECT CASE itself is separately mis-recovered -- see
            # wild/probes/probe_selfpchain.
            c.cur = addr
        # enclosing context's SP-save cell (if any) so a NESTED call used as
        # this call's own argument can freely overwrite it via its own
        # mov_mem_sp without corrupting the outer movm_imm-glue match once
        # control returns here (wild resume.exe)
        c.sp_save_stack.append(c.sp_save_cell)
        # Same nesting problem for a nested DEF FN call's own fn_args: its
        # fn_call will drain+clear fn_args, which would otherwise wipe out
        # the OUTER DEF FN call's own partially-staged args (t1_fnargcall).
        c.fn_args_stack.append(c.fn_args)
        c.fn_args = {}
        state.advance()
        return True
    if kind == "pop_bp":  # closes a call-staging temp frame: restore
        c.sp_save_cell = c.sp_save_stack.pop()  # the enclosing SP-
        c.fn_args = c.fn_args_stack.pop()  # save cell + fn_args
        state.advance()  # (wild resume.exe; t1_fnargcall)
        return True
    if kind in (
        "mov_si_sp",
        "add_si_sp",
        "sub_sp",
        "add_sp",
        "arg_push_temp",
        "mov_bx_sp",
        "les_si_ss_bx",
        "str_temp_free",
        "push_es",
        "push_cx",
        "push_ds",
        "push_ss",
        "mov_bp_sp",
        "str_free_temp",
        "bchk_base",  # Bounds: array-descriptor setup (F3.4)
        "far_movsi_si",  # by-ref index glue used by wild pw.exe
        "far_opaque",  # non-FP INT 3C helper selector
    ):
        if kind == "sub_sp" and c.cur is None:
            # `sub sp,N` reserving the outgoing-argument area OPENS a CALL
            # statement, and this family returns early -- before core.py's
            # generic top-of-statement `c.cur = addr` fallback -- so the
            # CallStmt would otherwise be recorded at whichever later op
            # happens to anchor it. That address is what an inline IF
            # immediately before the CALL names as its skip target, so the
            # target has to be the `sub sp` (the same anchoring `arg_ref` and
            # `mov_mem_sp` already do, for the same reason).
            #
            # Wild tbd73.exe, TBW73.INC:688-689, `SUB Makelmenu`'s
            # `CASE CHR$(73)`: `IF recpos < 1 THEN recpos = 1` is followed by
            # `CALL Drawlist(...)`, whose staging prologue runs 0xD1AF..0xD1D8
            # -- the IF skipped to 0xD1AF while the CallStmt was recorded at
            # 0xD1D8 (`jump target 0xd1af is not a statement start`).
            # Fixture t1_ifbeforecall.
            c.cur = addr
        state.advance()
        return True
    return False
