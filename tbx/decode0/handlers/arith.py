"""Integer and floating-point arithmetic / bit-op / stack handlers.

Handlers for ``decode_user_code``'s dispatch loop; each handler takes
the shared :class:`~tbx.decode0.core.DecodeState` plus the current
``op``/``addr``/``kind`` and returns ``True`` when it consumed the op.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from tbx import ir
from tbx.decode0.const import (
    ARR_BLOCK,
    _FREAD,
    _INPUTREAD,
    _JCC_RELOP_VALUE,
    _PREC,
    _READDATA,
)
from tbx.decode0.scan import _grp, _orient, _rgrp

if TYPE_CHECKING:
    from tbx.decode0.core import DecodeState


def int_alu(state: DecodeState, op, addr, kind) -> bool:
    """Dispatch family: movdx_m, movdxax, movdxbx, movbxax, movaxdx, movrr, movsim, addax_m, addsiax, subax_m, imul_m, imul_bp, movax_bp, idivbx, cmpax_m, inc_m, dec_m, negax, notax, notdx, oraxdx, xorax, xorah, shlsi, movmem_ax, reg_set."""
    if kind == "movdx_m":  # IMP left operand -> dx
        state.dx = state.loc(op[2])
        state.k += 1
        return True
    if kind == "movdxax":  # WAIT/INP port: ax -> dx
        state.dx, state.ax = state.ax, None
        state.k += 1
        return True
    if kind == "movdxbx":  # OUT port: bx -> dx
        state.dx, state.bx = state.bx, None
        state.k += 1
        return True
    if kind == "movbxax":  # LOCATE row -> bx
        state.bx, state.ax = state.ax, None
        state.k += 1
        return True
    if kind == "movaxdx":  # promote the \ quotient to MOD
        if not (isinstance(state.ax, ir.BinOp) and state.ax.op == "\\"):
            raise ValueError(f"movaxdx not following idiv at {addr:#x}")
        state.ax = ir.BinOp("MOD", state.ax.lhs, state.ax.rhs)
        state.k += 1
        return True
    if kind == "movrr":  # spill-protocol shuttle
        regs = {
            "ax": state.ax,
            "bx": state.bx,
            "cx": state.cx,
            "di": state.di,
            "si": state.si,
        }
        regs[op[2]], regs[op[3]] = regs[op[3]], None
        state.ax, state.bx, state.cx, state.di, state.si = (
            regs["ax"],
            regs["bx"],
            regs["cx"],
            regs["di"],
            regs["si"],
        )
        state.k += 1
        return True
    if kind == "spill_store":
        value = {"di": state.di}[op[2]]
        if value is None:
            raise ValueError(f"empty {op[2]} spill at {addr:#x}")
        state.reg_spills[op[3]] = value
        state.di = None
        state.k += 1
        return True
    if kind == "spill_load":
        try:
            value = state.reg_spills.pop(op[3])
        except KeyError:
            raise ValueError(f"unknown spill cell {op[3]:#x} at {addr:#x}") from None
        if op[2] == "cx":
            state.cx = value
        elif op[2] == "di":
            state.di = value
        else:
            raise ValueError(f"unsupported spill target {op[2]} at {addr:#x}")
        state.k += 1
        return True
    if kind == "movm_ax_temp":
        if state.ax is None:
            raise ValueError(f"empty integer temp argument at {addr:#x}")
        state.pend_args.append(state.ax)
        state.ax = None
        state.cur = None
        state.k += 1
        return True
    if kind == "movsim":
        # mov si,[disp16]: FOR-loop variable as a raw element index.
        state.si = state.loc(op[2])
        state.k += 1
        return True
    if kind == "movsi_bp":
        # mov si,[bp+d8]: LOCAL int as a raw element index (q_locidx)
        state.si = state.loc_local(op[2])
        state.k += 1
        return True
    if kind == "addax_m":  # fold LEFT; neg-aware = subtraction
        try:
            mem = state.loc(op[2])
        except ValueError:
            if op[2] < state.lay["pool_base"] - 4:
                raise
            # pooled int-literal LEFT operand: `15 - LEN(A$)` evaluates the
            # computed RIGHT first, negates, then adds the literal from the
            # const pool (witnessed t1_addpool) -- same fallback fpval/ifold
            # already have.
            mem = state.pool_lit(op[2])
        if isinstance(state.ax, ir.Neg):
            state.ax = ir.BinOp("-", mem, _rgrp("-", state.ax.operand))
        else:
            state.ax = ir.BinOp("+", mem, _rgrp("+", state.ax))
        state.k += 1
        return True
    if kind == "addsiax":
        # accumulate index legs, highest dim first (column-major):
        # rank 2: si=jspan + ax=i -> idx(i, j)
        # rank 3: si=kspan + ax=jspan -> jk(j, k); si=jk + ax=i -> idx(i, j, k)
        # (rank-3 witnessed t1_dim3v)
        if (
            isinstance(state.si, tuple)
            and state.si[0] == "kspan"
            and isinstance(state.ax, tuple)
            and state.ax[0] == "jspan"
            and state.ax[1] == state.si[1]
        ):
            state.si = ("jk", state.si[1], (state.ax[2], state.si[2]))
            state.ax = None
            state.k += 1
            return True
        if not (isinstance(state.si, tuple) and state.si[0] in ("jspan", "jk")):
            raise ValueError(f"add si,ax with si={state.si} ax={state.ax} at {addr:#x}")
        if (
            isinstance(state.ax, tuple)
            and state.ax[0] == "inorm"
            and state.ax[1] == state.si[1]
        ):
            i_expr = state.ax[2]
        elif not isinstance(state.ax, tuple) and state.ax is not None:
            i_expr = state.ax  # base-0: no i-lo sub
        else:
            raise ValueError(f"add si,ax with si={state.si} ax={state.ax} at {addr:#x}")
        rest = state.si[2] if state.si[0] == "jk" else (state.si[2],)
        state.si = ("idx", state.si[1], (i_expr, *rest))
        state.ax = None
        state.k += 1
        return True
    if kind == "subax_m":
        blk = next((b for b in state.slot_info if b <= op[2] < b + ARR_BLOCK), None)
        if blk is None:
            raise ValueError(f"sub ax,[{op[2]:#x}] outside array blocks at {addr:#x}")
        off = op[2] - blk
        if isinstance(state.ax, tuple) or state.ax is None:
            raise ValueError(f"far-IDX normalization of non-Expr ax at {addr:#x}")
        if off in (0x0E, 0x14):  # j - lo2 (or k - lo3), then * cumulative span
            span_off = 0x0C if off == 0x0E else 0x12  # span1 / span2 cell
            if (
                state.k + 1 >= len(state.ops)
                or state.ops[state.k + 1][1] != "imul_m"
                or state.ops[state.k + 1][2] != blk + span_off
            ):
                raise ValueError(f"jspan without imul at {addr:#x}")
            state.slot_info[blk]["subful"] = True  # lo-sub witness
            state.ax = ("jspan" if off == 0x0E else "kspan", blk, state.ax)
            state.k += 2
            return True
        if off == 0x08:  # i - lo1
            state.slot_info[blk]["subful"] = True  # lo-sub witness
            state.ax = ("inorm", blk, state.ax)
            state.k += 1
            return True
        raise ValueError(f"sub ax from unexpected cell offset {off:#x} at {addr:#x}")
    if kind == "imul_m":
        blk = next(
            (b for b in state.slot_info if op[2] in (b + 0x0C, b + 0x12)), None
        )
        if blk is not None:  # bare span multiply: OPTION BASE 0
            if isinstance(state.ax, tuple) or state.ax is None:  # far-IDX j-leg
                raise ValueError(f"span imul of non-Expr ax at {addr:#x}")
            state.ax = (
                "jspan" if op[2] == blk + 0x0C else "kspan",  # span2: t1_dim3v
                blk,
                state.ax,
            )
        else:
            try:
                mem = state.loc(op[2])
            except ValueError:
                if op[2] < state.lay["pool_base"] - 4:
                    raise
                # pooled int-literal LEFT operand: `180 * (A > 0)` evaluates
                # the materialized right first, then multiplies the literal
                # from the const pool (witnessed t1_imulpool, wild schart.exe)
                mem = state.pool_lit(op[2])
            state.ax = ir.BinOp("*", mem, _rgrp("*", state.ax))
        state.k += 1
        return True
    if kind == "imul_bp":  # imul word [bp+d8]: LOCAL int as the right operand
        state.ax = ir.BinOp("*", state.loc_local(op[2]), _rgrp("*", state.ax))
        state.k += 1
        return True
    if kind == "movax_bp":  # mov ax, [bp+d8]: LOCAL int read, e.g. as an
        state.ax = state.loc_local(op[2])  # expression's first term (t1_byref1)
        state.k += 1
        return True
    if kind == "idivbx":  # ax (dividend) \ bx (divisor) -> ax
        if state.bx is None:
            raise ValueError(f"idivbx without a bx divisor at {addr:#x}")
        state.ax = ir.BinOp("\\", state.ax, _rgrp("\\", state.bx))
        state.bx = None
        state.k += 1
        return True
    if kind == "cmpax_m":  # integer relational, mem side = source LHS
        if op[2] == 0x74:  # runtime cells, not user slots: ERR = [0074],
            mem: Any = ir.Err()  # ERL = [0072] (IF ERR = n, witnessed
        elif op[2] == 0x72:  # t1_errcmp / wild inv87.exe)
            mem = ir.Erl()
        else:
            mem = state.loc(op[2])
        nxt = state.ops[state.k + 1] if state.k + 1 < len(state.ops) else None
        # AND-chain 2nd+ term (wild schart.exe): the running accumulator sits
        # in bx (OR-chains need no accumulator, they resolve by pure
        # short-circuit jumps -- t1_orchain). The compare's own flags survive
        # a plain register shuttle, so the compiler round-trips ax<->bx
        # (mov ax,bx; mov bx,ax -- a no-op restoring bx's value, byte-exact
        # boilerplate) between the compare and the value materialization;
        # skip over it and let the generic movrr/movbxax handlers process it.
        j = state.k + 1
        while j < len(state.ops) and state.ops[j][1] in ("movrr", "movbxax"):
            j += 1
        shuffled = (
            j > state.k + 1
            and j < len(state.ops)
            and state.ops[j][1] == "movax"
            and state.ops[j][2] == 0xFFFF
        )
        if (nxt is not None and nxt[1] == "movax" and nxt[2] == 0xFFFF) or shuffled:
            state.pend_icmp = (mem, state.ax)  # relational-value form
            state.ax = None
            state.k += 1
            return True
        # IF forms: cmp ax,[mem] flags are rhs-lhs (REVERSED, like the FP
        # rows and unlike cmpax_bx's forward order) -- the skip map mirrors
        # cmpax_bp's and the direct map coincides with _JCC_RELOP_VALUE;
        # only "=" is witnessed (t1_errcmp direct, inv87 skip), the other
        # rows follow the same orientation derivation
        if nxt is not None and nxt[1] == "jcc":
            cc = nxt[2]
            j2 = state.ops[state.k + 2] if state.k + 2 < len(state.ops) else None
            if j2 is not None and j2[1] == "jmp" and nxt[3] == j2[0] + 3:
                skiprel = {
                    0x74: "<>", 0x75: "=", 0x7F: ">=",
                    0x7D: ">", 0x7C: "<=", 0x7E: "<",
                }
                if cc not in skiprel:
                    raise ValueError(f"cmpax_m IF jcc {cc:02x} at {addr:#x}")
                state.put(
                    ir.IfGoto(
                        ir.RelOp(skiprel[cc], mem, state.ax), ("addr", j2[2])
                    ),
                    state.cur,
                )
                state.ax = None
                state.cur = None
                state.k += 3
                return True
            if cc in _JCC_RELOP_VALUE:  # direct: taken = THEN <line>
                state.put(
                    ir.IfGoto(
                        ir.RelOp(_JCC_RELOP_VALUE[cc], mem, state.ax),
                        ("addr", nxt[3]),
                    ),
                    state.cur,
                )
                state.ax = None
                state.cur = None
                state.k += 2
                return True
        raise ValueError(f"cmpax_m without a value/IF consumer at {addr:#x}")
    if kind == "cmpax_bp":  # cmp ax,[bp+d8]: relational against a LOCAL int
        # (q_loccmp). The compiler evaluates the SOURCE RHS into ax and
        # compares the LOCAL as memory, so flags are rhs-vs-lhs; the emitted
        # skip-goto must keep the LOCAL on the LEFT (byte-identical respell),
        # which needs a mirrored negation map -- the shared _JCC_RELOP signed
        # rows assume cmpax_bx's forward flag order, so the IF form consumes
        # its own jcc+jmp here. Value form (movax FFFF follows) keeps
        # cmpax_m's (mem, ax) source order.
        nxt = state.ops[state.k + 1] if state.k + 1 < len(state.ops) else None
        local = state.loc_local(op[2])
        if nxt is not None and nxt[1] == "movax" and nxt[2] == 0xFFFF:
            state.pend_icmp = (local, state.ax)
            state.ax = None
            state.k += 1
            return True
        skiprel = {0x74: "<>", 0x75: "=", 0x7F: ">=", 0x7D: ">", 0x7C: "<=", 0x7E: "<"}
        if (
            nxt is None
            or nxt[1] != "jcc"
            or nxt[2] not in skiprel
            or state.k + 2 >= len(state.ops)
            or state.ops[state.k + 2][1] != "jmp"
            or nxt[3] != state.ops[state.k + 2][0] + 3
        ):
            raise ValueError(f"cmpax_bp without an IF jcc+skip-jmp at {addr:#x}")
        state.put(
            ir.IfGoto(
                ir.RelOp(skiprel[nxt[2]], local, state.ax),
                ("addr", state.ops[state.k + 2][2]),
            ),
            state.cur,
        )
        state.ax = None
        state.cur = None
        state.k += 3
        return True
    if kind == "addax_bp":  # add ax,[bp+d8]: fold a LOCAL int LEFT (q_loccmp)
        if isinstance(state.ax, ir.Neg):
            state.ax = ir.BinOp(
                "-", state.loc_local(op[2]), _rgrp("-", state.ax.operand)
            )
        else:
            state.ax = ir.BinOp("+", state.loc_local(op[2]), _rgrp("+", state.ax))
        state.k += 1
        return True
    if kind == "cmpax_bx":  # integer IF compare, both sides ax-computed: the
        # source RHS evaluates first and shuttles to bx, LHS lands in ax, and
        # the signed Jcc rides _JCC_RELOP's 7C-7F rows (witnessed t1_cmpax)
        state.pend_cmp = (state.ax, state.bx)
        state.ax = state.bx = None
        state.k += 1
        return True
    if kind == "inc_m":
        if state.fors and state.fors[-1]["v"] == op[2]:
            # Integer FOR-NEXT increment -- implicit in BASIC; consume
            # silently (the NEXT stmt is emitted on the cmp_mi8 guard above).
            state.k += 1
            return True
        # INCR normalization: bare INC [disp16] outside a FOR context
        # compiles `X = X + 1` (witnessed t1_incr1)
        var = state.loc(op[2])
        state.put(ir.Assign(var, ir.BinOp("+", var, ir.Lit(1))), state.cur)
        state.cur = None
        state.k += 1
        return True
    if kind == "inc_bp":
        # LOCAL-var FOR-NEXT increment (q_locidx). A bare inc [bp+d8] outside
        # a FOR is unwitnessed (LOCAL `X% = X% + 1` compiles to addm_ax_bp,
        # t1_local1) -- fail loud.
        if state.fors and state.fors[-1]["v"] == op[2]:
            state.k += 1
            return True
        raise ValueError(f"inc [bp+{op[2]}] outside a FOR at {addr:#x}")
    if kind == "dec_m":
        # DECR normalization: bare DEC [disp16] compiles `X = X - 1`; never
        # witnessed inside a FOR (negative-step FOR-NEXT is a separate,
        # unwitnessed shape) so any FOR-frame match is fail-loud
        if state.fors and state.fors[-1]["v"] == op[2]:
            raise ValueError(f"dec_m matches the open FOR's loop var at {addr:#x}")
        var = state.loc(op[2])
        state.put(ir.Assign(var, ir.BinOp("-", var, ir.Lit(1))), state.cur)
        state.cur = None
        state.k += 1
        return True
    if kind == "addm_i8":
        # Integer FOR-NEXT increment for a literal STEP other than +-1 (those
        # use inc_m/dec_m instead): `add word [I%], step` at the open FOR's
        # test address. Rewrite the already-emitted ir.For statement's step
        # in place -- it was provisionally Lit(1) when the header was folded,
        # before this NEXT-side evidence was available (q_forstep/
        # q_forstepneg). No bare (non-FOR) form is witnessed; fail loud.
        if not (state.fors and state.fors[-1]["v"] == op[2]):
            raise ValueError(f"unhandled addm_i8 (not an open FOR's var) at {addr:#x}")
        f = state.fors[-1]
        old = state.stmts[f["idx"]]
        state.stmts[f["idx"]] = ir.For(old.var, old.init, old.limit, ir.Lit(op[3]))
        f["step"] = op[3]
        state.k += 1
        return True
    if kind == "negax":  # subtraction setup
        state.ax = ir.Neg(state.ax)
        state.k += 1
        return True
    if kind == "notax":  # unary NOT of the accumulator
        state.ax = ir.Not(state.ax)
        state.k += 1
        return True
    if kind == "notdx":  # NOT the dx operand in place
        state.dx = ir.Not(state.dx)
        state.k += 1
        return True
    if kind == "oraxdx":  # completes IMP as `(NOT A) OR B`
        state.ax = ir.BinOp("OR", state.dx, _rgrp("OR", state.ax))
        state.dx = None
        state.k += 1
        return True
    if kind == "xorax":  # xor ax,ax = literal 0
        state.ax = ir.Lit(0)
        state.k += 1
        return True
    if kind == "xorah":  # INP result widen: lift no-op
        state.k += 1
        return True
    if kind == "shlsi":
        # `shl si[; shl si[; shl si]]; (moves_m blk | addsi base); <terminal>` --
        # one shl for a 2-byte (INTEGER) element stride (x2, wild number.exe:
        # the single-shl case had no witness until now, so the gate below
        # unconditionally required a second shl), two for 4-byte (single/
        # string-descriptor), the optional third for 8-byte (double).
        if state.k + 1 >= len(state.ops):
            raise ValueError(f"shl si outside an element access at {addr:#x}")
        if state.ops[state.k + 1][1] == "shlsi":
            ao = (
                3
                if state.k + 2 < len(state.ops)
                and state.ops[state.k + 2][1] == "shlsi"
                else 2
            )
        else:
            ao = 1
        if state.k + ao + 1 >= len(state.ops) or state.ops[state.k + ao][1] not in (
            "moves_m",
            "addsi",
        ):
            raise ValueError(f"shl si outside an element access at {addr:#x}")
        far = state.ops[state.k + ao][1] == "moves_m"
        if far:
            blk = state.ops[state.k + ao][2]
        else:  # near static: add si, <base>
            blk = next(
                (
                    b
                    for b, v in state.slot_info.items()
                    if v.get("base") == state.ops[state.k + ao][2]
                ),
                None,
            )
            if blk is None:
                raise ValueError(
                    f"add si,{state.ops[state.k + ao][2]:#x} matches no static "
                    f"base at {addr:#x}"
                )
        if not isinstance(state.si, tuple) and state.si is not None:
            # raw index in si: a plain subscript. 1-D, or a
            # Bounds checked access where the earlier dims were stashed in
            # bchk_subs (F3.5): si is the final (first-source) subscript, the
            # stash the rest in reverse (column-major collects dim-N..dim-1).
            if state.bchk_subs:
                subs = tuple(reversed(state.bchk_subs + [state.si]))
                state.bchk_subs = []
                if blk not in state.slot_info or state.slot_info[blk]["rank"] != len(
                    subs
                ):
                    raise ValueError(
                        f"bounds subscript count != array rank at {addr:#x}"
                    )
                state.si = ("idx", blk, subs)
            else:
                if blk not in state.slot_info or state.slot_info[blk]["rank"] != 1:
                    raise ValueError(
                        f"raw element index on non-rank-1 block at {addr:#x}"
                    )
                state.si = ("idx", blk, (state.si,))
        if (
            not (isinstance(state.si, tuple) and state.si[0] == "idx")
            or state.si[1] != blk
        ):
            raise ValueError(f"shl si outside an element access at {addr:#x}")
        a = state.slot_info[blk]
        if any(not isinstance(e, ir.Lit) for e in state.si[2]):
            a["varacc"] = True  # variable-subscript witness
        ref = ir.ArrayRef(a["name"], state.si[2])
        state.si = None
        sik = state.ops[state.k + ao + 1]
        pre = "far_" if far else ""
        if sik[1] in ("far_spush", "far_strassign") or (
            not far and sik[1] == "strassign"
        ):  # near strassign: SI already points at the element descriptor
            # (SUB-local static string array, witnessed q_locidx)
            if not a.get("str"):
                raise ValueError(f"string op on numeric array at {addr:#x}")
            if sik[1] == "far_spush":
                state.sstack.append(ref)
            else:
                v = state.sstack.pop()
                if v is _FREAD:  # INPUT# far string target
                    state._fread_target(ref)
                else:
                    state.put(ir.Assign(ref, v), state.cur)
                state.cur = None
        elif sik[1] in (pre + "fld_si", pre + "fld_si64", pre + "fild_si32"):
            state.stack.append(ref)
        elif sik[1] in (pre + "fstp_si", pre + "fstp_si64", pre + "fstp_si32"):
            v = state.stack.pop()
            if v is _FREAD:  # INPUT# far numeric target
                state._fread_target(ref)
            elif v is _READDATA:  # READ far numeric target
                state._readdata_target(ref)
            elif v is _INPUTREAD:  # console INPUT element target (t1_inparr)
                state._input_target(ref, is_str=False)
            else:
                state.put(ir.Assign(ref, v), state.cur)
            state.cur = None
        elif sik[1] == pre + "fold_si":
            state.stack.append(_orient(sik[2], ref, state.stack.pop()))
        elif sik[1] == pre + "fold_n_si":  # mem = RIGHT operand
            state.stack.append(ir.BinOp(sik[2], state.stack.pop(), ref))
        elif sik[1] in (pre + "fcomp_si", pre + "fcomp_si64"):
            # IF on an array element (m64 witnessed t1_dblar2)
            state.pend_cmp = (ref, state.stack.pop())
        elif sik[1] == "rt" and sik[2] == 0x9C:
            # push (var desc): a VARIABLE-indexed static string array element
            # used as a string value (PRINT item, string arg, ...) -- same
            # push-then-consume shape as the constant-index case (core.py's
            # movsi + rt-0x9C), just via a computed si instead of a fixed
            # disp16. The following op (the actual consumer) runs through the
            # ordinary dispatch loop, same as any other sstack push.
            if not a.get("str"):
                raise ValueError(f"string op on numeric array at {addr:#x}")
            state.sstack.append(ref)
        elif sik[1] == pre + "movm_ax_si":
            # mov [si], ax (near) / mov es:[si], ax (far, by-ref param array
            # arg): the INTEGER write sibling of the rt-0x9C string read
            # above -- `ARRAY%(i) = <int expr>` via a computed index (wild
            # number.exe). ax already holds the materialized RHS.
            state.put(ir.Assign(ref, state.ax), state.cur)
            state.ax = None
            state.cur = None
        elif sik[1] == pre + "movax_si":
            # mov ax, [si] (near) / mov ax, es:[si] (far): the INTEGER read
            # sibling of movm_ax_si above -- `X% = ARRAY%(i)` via a computed
            # index (wild number.exe), e.g. as an expression's first term.
            state.ax = ref
        elif sik[1] == pre + "addax_si":
            # add ax, [si] (near) / add ax, es:[si] (far): arithmetic fold
            # of a computed array element (`ARRAY%(i) + <expr>`, wild
            # number.exe), mem = the array ref (left operand).
            state.ax = ir.BinOp("+", ref, _rgrp("+", state.ax))
        elif sik[1] == pre + "cmpax_si":
            # cmp ax, [si] (near) / cmp ax, es:[si] (far): relational against
            # a computed array element (`IF ARRAY%(i) = ... THEN ...`, wild
            # number.exe) -- same (mem, ax) REVERSED-flag orientation as
            # cmpax_m, mem = the array ref. Only the IF forms are witnessed
            # (jcc+skip-jmp here; a bare direct jcc follows the same
            # cmpax_m-derived map) -- the "materialize as a value" form
            # (movax 0xFFFF) has no witness for a computed array element and
            # is left to the final raise below.
            k2 = state.k + ao + 2
            nxt = state.ops[k2] if k2 < len(state.ops) else None
            if nxt is not None and nxt[1] == "jcc":
                cc = nxt[2]
                j2 = state.ops[k2 + 1] if k2 + 1 < len(state.ops) else None
                if j2 is not None and j2[1] == "jmp" and nxt[3] == j2[0] + 3:
                    skiprel = {
                        0x74: "<>", 0x75: "=", 0x7F: ">=",
                        0x7D: ">", 0x7C: "<=", 0x7E: "<",
                    }
                    if cc not in skiprel:
                        raise ValueError(f"cmpax_si IF jcc {cc:02x} at {addr:#x}")
                    state.put(
                        ir.IfGoto(ir.RelOp(skiprel[cc], ref, state.ax), ("addr", j2[2])),
                        state.cur,
                    )
                    state.ax = None
                    state.cur = None
                    state.k = k2 + 2
                    return True
                if cc in _JCC_RELOP_VALUE:
                    state.put(
                        ir.IfGoto(
                            ir.RelOp(_JCC_RELOP_VALUE[cc], ref, state.ax),
                            ("addr", nxt[3]),
                        ),
                        state.cur,
                    )
                    state.ax = None
                    state.cur = None
                    state.k = k2 + 1
                    return True
            raise ValueError(f"cmpax_si without an IF jcc consumer at {addr:#x}")
        elif sik[1] == "movm_ds":
            # `mov [disp16], ds`: DS spilled to a scratch slot ahead of an
            # ES-aliased near-array access -- the first operand of `SWAP
            # ARRAY%(i), ARRAY%(j)` (wild number.exe/q_arrswap). Stage this
            # ref and keep scanning; the second operand's own shl/addsi
            # chain (below) ends in the matching `moves_m` that restores
            # DS->ES so both computed addresses can be reached via ES.
            state.pend_swap = ref
        elif sik[1] == "moves_m" and state.pend_swap is not None:
            # ES restored from the scratch slot: the second operand's index
            # chain just completed. The fixed 4-op tail that follows does
            # the actual swap through the ES alias (mov bx,ax; mov
            # ax,es:[bx]; xchg ax,[si]; mov es:[bx],ax) -- q_arrswap.
            tail = [t[1] for t in state.ops[state.k + ao + 2 : state.k + ao + 6]]
            if tail != ["movbxax", "far_movax_bx", "xchgsi", "far_movm_ax_bx"]:
                raise ValueError(f"array SWAP tail mismatch at {addr:#x}")
            extra = 0
            if ao == 2:
                # 4-byte element (SINGLE): a second word-swap round at +2
                # handles the high word (wild number.exe).
                tail2 = [
                    t[1] for t in state.ops[state.k + ao + 6 : state.k + ao + 9]
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
            state.put(ir.Swap(state.pend_swap, ref), state.cur)
            state.pend_swap = None
            state.cur = None
            state.k += ao + 6 + extra
            return True
        else:
            raise ValueError(f"element access: unexpected op {sik[1]} at {sik[0]:#x}")
        state.k += ao + 2
        return True
    if kind == "movmem_ax":  # int->FP bridge
        nxt = state.ops[state.k + 1] if state.k + 1 < len(state.ops) else None
        if op[2] != 0x2C or nxt is None or nxt[1] != "fild" or nxt[2] != 0x2C:
            raise ValueError(f"unexpected mov [imm],ax at {addr:#x}")
        # A round-trip flagged by the fistp[2C] arm is CINT(x); a bare int
        # bridge (ASC-style, no preceding fistp) pushes the value as-is.
        if state.cint_round:
            state.cint_round = False
            state.stack.append(ir.Call("CINT", (state.ax,)))
        else:
            state.stack.append(state.ax)
        state.ax = None
        state.k += 2
        return True
    if kind == "reg_set":  # REG n, value
        state.put(ir.RegSet(state.ax, state.stack.pop()), state.cur)
        state.ax = None
        state.cur = None
        state.k += 1
        return True
    return False


def int_bitwise_m(state: DecodeState, op, addr, kind) -> bool:
    """Dispatch family: andax_m, orax_m, xorax_m."""
    if kind in ("andax_m", "orax_m", "xorax_m"):  # bitwise fold, mem on the left
        comb = {"andax_m": "AND", "orax_m": "OR", "xorax_m": "XOR"}[kind]
        state.ax = ir.BinOp(comb, state.loc(op[2]), _rgrp(comb, state.ax))
        state.k += 1
        return True
    return False


def int_bitwise_bx(state: DecodeState, op, addr, kind) -> bool:
    """Dispatch family: andaxbx, oraxbx, xoraxbx, addaxbx, subaxbx, imulbx."""
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
        if state.ax is None or state.bx is None:
            raise ValueError(f"ax,bx combine with empty regs at {addr:#x}")
        state.ax = ir.BinOp(comb, state.ax, _rgrp(comb, state.bx))
        state.bx = None
        state.k += 1
        return True
    return False


def fp_math(state: DecodeState, op, addr, kind) -> bool:
    """Dispatch family: fistp, fpow, fwait, fstp_temp."""
    if kind == "fistp":  # IDX% scratch: array idx OR FP->int
        if op[2] != 0x2C:
            raise ValueError(f"FISTP to unexpected scratch [{op[2]:#x}]")
        idx = state.stack.pop()
        nxt3 = [o[1] for o in state.ops[state.k + 1 : state.k + 4]]
        if nxt3 == ["fwait", "movaxmem", "movm_ax"]:  # FP->int assign
            if state.ops[state.k + 2][2] != 0x2C:
                raise ValueError(f"FP->int bridge mismatch at {addr:#x}")
            tgt = state.ops[state.k + 3][2]
            if (
                state.dim_frame is not None
                and state.dim_frame["block"]
                <= tgt
                < state.dim_frame["block"] + ARR_BLOCK
            ):
                state.dim_frame["cells"][tgt - state.dim_frame["block"]] = idx  # bound
            elif tgt in (0x88, 0x94, 0xA0, 0xAC, 0xB8, 0xC4):  # COLOR/VIEW cell,
                state.color_cells[tgt] = idx  # rounded via CINT (a non-integer arg)
            elif idx is _FREAD:  # INPUT# int target via the bridge (t1_fileint)
                state._fread_target(state.loc(tgt))
                state.cur = None
            elif idx is _READDATA:  # READ int target via the bridge
                state._readdata_target(state.loc(tgt))
                state.cur = None
            else:
                state.put(ir.Assign(state.loc(tgt), idx), state.cur)
                state.cur = None
            state.k += 4
            return True
        # Element-subscript bridge: optional spill shuttles (the a1 below clobbers
        # ax, so in-flight tokens move through bx/cx first), then
        # fwait + a1 2c lands the integer in ax; the symbolic machine (subax_m /
        # movsiax / addsiax / shlsi) takes it from there, ending in either the
        # far (moves_m) or the near static (addsi) terminal.
        j = state.k + 1
        while j < len(state.ops) and state.ops[j][1] in ("movrr", "movbxax"):
            j += 1
        nxt2 = state.ops[j + 2][1] if j + 2 < len(state.ops) else None
        if (
            [o[1] for o in state.ops[j : j + 2]] == ["fwait", "movaxmem"]
            and state.ops[j + 1][2] == 0x2C
            and nxt2 != "movm_ax"
        ):
            # CINT(x): the round-trip tail is movmem_ax[0x2C]; fild[0x2C] (round
            # FP->int->FP). Flag it so the movmem_ax bridge wraps the value in
            # CINT(). A genuine subscript bridge continues with other ops here,
            # and the ASC-style int bridge has no preceding fistp at all.
            if (
                j + 3 < len(state.ops)
                and state.ops[j + 2][1] == "movmem_ax"
                and state.ops[j + 2][2] == 0x2C
                and state.ops[j + 3][1] == "fild"
                and state.ops[j + 3][2] == 0x2C
            ):
                state.cint_round = True
            for sh in state.ops[state.k + 1 : j]:  # apply the shuttles in order
                regs = {
                    "ax": state.ax,
                    "bx": state.bx,
                    "cx": state.cx,
                    "di": state.di,
                    "si": state.si,
                }
                dst, src = ("bx", "ax") if sh[1] == "movbxax" else (sh[2], sh[3])
                regs[dst], regs[src] = regs[src], None
                state.ax, state.bx, state.cx, state.di, state.si = (
                    regs["ax"],
                    regs["bx"],
                    regs["cx"],
                    regs["di"],
                    regs["si"],
                )
            state.ax = idx
            state.k = j + 2
            return True
        raise ValueError(f"IDX% bridge mismatch at {addr:#x}")
    if kind == "fpow":  # ^ : top = base, below = exponent
        lhs = state.stack.pop()
        rhs = state.stack.pop()
        state.stack.append(ir.BinOp("^", lhs, _grp(rhs)))
        state.k += 1
        return True
    if kind == "fwait":  # stray x87 sync: no semantics
        state.k += 1  # (bridge templates consume their
        return True
    if kind == "fstp_temp":  # FSTP [ss:si]: materialized literal CALL arg
        state.pend_args.append(state.stack.pop())
        state.cur = None
        state.k += 1
        return True
    return False


def fp_bp(state: DecodeState, op, addr, kind) -> bool:
    """Dispatch family: fld_bp, fstp_bp, fold_bp, fold_n_bp, fcomp_bp, fild_bp."""
    if kind == "fild_bp":  # LOCAL int onto the FP stack, e.g. for PRINT
        if state.proc_frame is None:
            raise ValueError(f"fild_bp outside a SUB body at {addr:#x}")
        if state.cur is None:  # may open a statement (e.g. PRINT A% as an
            state.cur = addr  # IF's skip-goto target, q_loccmp)
        state.stack.append(state.loc_local(op[2]))
        state.k += 1
        return True
    if kind in ("fld_bp", "fstp_bp", "fold_bp", "fold_n_bp", "fcomp_bp"):
        bp_off = op[2] if kind in ("fld_bp", "fstp_bp", "fcomp_bp") else op[3]
        if state.fn_frame is not None:  # DEF FN body: param read / result / fold
            if bp_off > state.fn_frame["max_off"]:
                state.fn_frame["max_off"] = bp_off
            pvar = ir.Var(f"P{bp_off:02X}")
            if kind == "fld_bp":
                state.stack.append(pvar)
            elif kind == "fstp_bp":
                if bp_off != 0:
                    raise ValueError(f"FSTP [bp+{bp_off}] in DEF FN body at {addr:#x}")
                if state.fn_frame["block"]:  # multi-line: `FN = expr` result statement
                    state.put(ir.FnResult(state.stack.pop()), state.cur)
                    state.cur = None
                else:  # single-line: inline result expr
                    state.fn_frame["result"] = state.stack.pop()
            elif kind == "fold_bp":  # param as LEFT operand
                state.stack.append(_orient(op[2], pvar, state.stack.pop()))
            elif kind == "fold_n_bp":  # non-R: param is the RIGHT operand
                top = state.stack.pop()
                if isinstance(top, ir.BinOp) and _PREC[top.op] < _PREC[op[2]]:
                    top = ir.Group(top)
                state.stack.append(ir.BinOp(op[2], top, pvar))
            else:  # fcomp_bp (EXIT DEF tests)
                state.pend_cmp = (pvar, state.stack.pop())
        else:  # main frame: FN-call staging
            if kind == "fstp_bp":  # stage a literal/computed call arg
                state.fn_args[bp_off] = state.stack.pop()
            elif kind == "fld_bp":  # reload of the FN result: redundant glue
                pass
            else:
                raise ValueError(f"unexpected {kind} in main body at {addr:#x}")
        state.k += 1
        return True
    return False


def far_fp(state: DecodeState, op, addr, kind) -> bool:
    """Dispatch family: far_fld, far_fstp, far_fold."""
    if kind in ("far_fld", "far_fstp", "far_fold"):  # 1-D const subscript
        if state.pend_es is None:
            raise ValueError(f"far FP op without ES at {addr:#x}")
        a = state.r_arrs[state.pend_es]
        if a["rank"] != 1:
            raise ValueError(f"direct-disp far access on rank-{a['rank']} array")
        disp = op[2] if kind != "far_fold" else op[3]
        ref = ir.ArrayRef(a["name"], (ir.Lit(disp // 4 + a["lo"][0]),))
        state.pend_es = None
        if kind == "far_fld":
            state.stack.append(ref)
        elif kind == "far_fstp":
            state.put(ir.Assign(ref, state.stack.pop()), state.cur)
            state.cur = None
        else:
            state.stack.append(_orient(op[2], ref, state.stack.pop()))
        state.k += 1
        return True
    return False


def stack_ops(state: DecodeState, op, addr, kind) -> bool:
    """Dispatch family: mov_si_sp, add_si_sp, sub_sp, add_sp, arg_push_temp, mov_bx_sp, les_si_ss_bx, str_temp_free, push_bp, pop_bp, mov_bp_sp, str_free_temp, bchk_base."""
    if kind in (
        "mov_si_sp",
        "add_si_sp",
        "sub_sp",
        "add_sp",
        "arg_push_temp",
        "mov_bx_sp",
        "les_si_ss_bx",
        "str_temp_free",
        "push_bp",
        "push_es",
        "push_ds",
        "pop_bp",
        "mov_bp_sp",
        "str_free_temp",
        "bchk_base",  # Bounds: array-descriptor setup (F3.4)
    ):
        state.k += 1
        return True
    return False
