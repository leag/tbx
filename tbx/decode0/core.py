"""decode_user_code: the top-level decode orchestrator."""

from __future__ import annotations
import struct
from dataclasses import dataclass
from typing import Any, cast

from tbx import ir
from tbx.decode0.const import (
    ARR_BLOCK,
    VAR_BASE,
    _FREAD,
    _JCC_RELOP,
    _JCC_RELOP_TRUE,
    _PREC,
    _PUT_ACTIONS,
    _READDATA,
)
from tbx.decode0.dialect import find_prologue
from tbx.decode0.scan import _grp, _orient, _scan
from tbx.decode0 import handlers, select_case
from tbx.decode0.datapool import _read_data_pool
from tbx.decode0.layout import (
    _blit_at,
    _fill_lines,
    _layout,
    _line_table,
    _pool_has_word,
)
from tbx.decode0.meta import Program, _meta_stmts, _toggles
from tbx.decode0.lift import (
    _apply_exit_folds,
    _fold_if,
    _is_for_header,
    _lift_midblock_troff,
    _lift_next,
    _resolve_targets,
)
from tbx.decode0.rename import _slot, _str_lit, canonical_rename


@dataclass
class DecodeState:
    """Mutable register file for :func:`decode_user_code` -- every field is a
    persistent decode-loop variable, initialized in the setup block before the
    main dispatch loop and shared by the handler modules."""

    addrs: Any = None
    arrs: Any = None
    ax: Any = None
    bchk_subs: Any = None
    bx: Any = None
    cases: Any = None
    cc_hooks: Any = None
    cint_round: Any = None
    color_cells: Any = None
    commits: Any = None
    cur: Any = None
    cx: Any = None
    desc_disps: Any = None
    dia: Any = None
    dim_frame: dict[str, Any] | None = None
    discard_strs: Any = None
    dos: Any = None
    ds: Any = None
    dsd: Any = None
    dx: Any = None
    exe: Any = None
    exit_folds: Any = None
    fn_args: Any = None
    fn_frame: dict[str, Any] | None = None
    fors: Any = None
    has_procs: Any = None
    have_fre: Any = None
    hook_seq: Any = None
    ifs: Any = None
    k: Any = None
    lay: Any = None
    main_start: Any = None
    metas: Any = None
    nfn: Any = None
    nsub: Any = None
    ops: Any = None
    option_base: Any = None
    pend_arg: Any = None
    pend_args: Any = None
    pend_bool: Any = None
    pend_cmp: Any = None
    pend_dataread: Any = None
    pend_es: Any = None
    pend_filein: Any = None
    pend_fnum: Any = None
    pend_icmp: Any = None
    pend_input: Any = None
    pend_print: dict[str, Any] | None = None
    pend_using: Any = None
    prev_dim_end: Any = None
    proc_frame: Any = None
    proc_names: Any = None
    proc_str_offs: Any = None
    r_arrs: Any = None
    si: Any = None
    slot_info: Any = None
    sp_save_cell: Any = None
    ss_base: Any = None
    sstack: Any = None
    stack: Any = None
    start: Any = None
    stmt_addr: Any = None
    stmts: Any = None
    toggles: Any = None
    trace_tbl: Any = None
    whiles: Any = None

    def pool_lit(self, disp):
        return ir.Lit(struct.unpack_from("<h", self.exe, self.dsd + disp)[0])

    def pool_lit32(self, disp):
        """Pooled signed-32 integer literal (long-integer const pool)."""
        return ir.Lit(struct.unpack_from("<i", self.exe, self.dsd + disp)[0])

    def fpval(self, disp):
        """FP mem operand: variable/element via loc(), or a pooled IEEE-754 single
        literal in the pool window."""
        try:
            return self.loc(disp)
        except ValueError:
            if disp >= self.lay["pool_base"] - 4:
                return ir.Lit(
                    ir.f32_dec(self.exe[self.dsd + disp : self.dsd + disp + 4])
                )
            raise

    def fpval64(self, disp):
        """Double FP mem operand: variable/element via loc(), or a pooled IEEE-754
        double literal (8 LE bytes) in the pool window. fpval at f64 width."""
        try:
            return self.loc(disp)
        except ValueError:
            if disp >= self.lay["pool_base"] - 4:
                return ir.DblLit(struct.unpack_from("<d", self.exe, self.dsd + disp)[0])
            raise

    def loc(self, disp):
        """Classify a [disp16] operand: scalar slot -> Var (with % suffix for 2-byte
        integer slots / $ for string descriptor slots); array element ->
        ArrayRef with constant subscripts recovered from the layout,
        lo-aware and column-major (r = (i-lo1) + (j-lo2)*span)."""
        if disp in self.lay["strs"]:
            return ir.Var(_slot(disp) + "$")
        if disp in self.lay["scalars"]:
            w = self.lay["scalars"][disp]
            suffix = (
                "%"
                if w == 2
                else "#"
                if w == 8
                else "&"
                if disp in self.lay["long_slots"]
                else ""
            )
            return ir.Var(_slot(disp) + suffix)
        for a in self.arrs:
            esz = a["esz"]
            if a["base"] <= disp < a["base"] + esz * a["count"]:
                r = (disp - a["base"]) // esz
                if a["rank"] == 1:
                    return ir.ArrayRef(a["name"], (ir.Lit(a["lo"][0] + r),))
                return ir.ArrayRef(
                    a["name"],
                    (
                        ir.Lit(a["lo"][0] + r % a["span"]),
                        ir.Lit(a["lo"][1] + r // a["span"]),
                    ),
                )
        raise ValueError(f"displacement {disp:#x} is neither scalar nor array element")

    def flush_pending(self):
        """A trailing-';' print has no flush vector: the chain is proven
        closed only when the next statement completes, so finalize lazily with
        newline=False. (Consecutive same-leg prints merge -- byte-identical.)
        INPUT# target chains end the same way: the last store has no
        terminator, so they too finalize on the next completed statement (with a
        forced flush at any [0060] store so adjacent statements never merge)."""
        if self.pend_dataread is not None:
            pr, self.pend_dataread = self.pend_dataread, None
            if not pr["targets"]:
                raise ValueError("READ chain closed without any stored target")
            self.stmts.append(ir.Read(tuple(pr["targets"])))
            self.addrs.append(pr["start"])
        if self.pend_filein is not None:
            pf, self.pend_filein = self.pend_filein, None
            if not pf["targets"]:
                raise ValueError("INPUT# chain closed without any stored target")
            self.stmts.append(ir.InputFile(pf["num"], tuple(pf["targets"])))
            self.addrs.append(pf["start"])
            self.pend_fnum = None
        if self.pend_print is not None:
            pp, self.pend_print = self.pend_print, None
            if pp.get("mode") == "write":  # WRITE / WRITE# has no trailing-';' form:
                self.stmts.append(ir.Write(tuple(pp["items"]), file=pp["file"]))
            elif pp.get("mode") == "lprint":  # LPRINT closes only on its own B9
                raise ValueError("LPRINT chain not flushed on b9")
            else:
                self.stmts.append(
                    ir.Print(tuple(pp["items"]), newline=False, file=pp["file"])
                )
            self.addrs.append(pp["start"])
        if self.pend_using is not None:
            pu, self.pend_using = self.pend_using, None
            self.stmts.append(
                ir.PrintUsing(
                    pu["fmt"], tuple(pu["values"]), file=pu["file"], newline=False
                )
            )
            self.addrs.append(pu["start"])

    def put(self, stmt, addr):
        self.flush_pending()
        self.stmts.append(stmt)
        self.addrs.append(addr)

    def _fread_target(self, ref: object) -> None:  # open INPUT# target chain
        assert self.pend_filein is not None
        self.pend_filein["targets"].append(ref)

    def _readdata_target(self, ref: object) -> None:  # open READ target chain
        assert self.pend_dataread is not None
        self.pend_dataread["targets"].append(ref)

    # decode a pooled string literal at descriptor `desc`; desc and ss_base are ints
    # wherever a string literal is present (else this is unreached)
    def _pool_str(self, desc: object) -> ir.StrLit:
        return _str_lit(self.exe, self.dsd, cast(int, desc), cast(int, self.ss_base))

    def vdisp(self, node):  # placeholder Var -> DS displacement
        return int(node.name[1:].rstrip("%&#"), 16)


def _finalize(state: DecodeState, addr) -> Program:
    """Program epilogue: static-DIM re-emit, control-flow folds, target
    resolution and canonical rename -> the finished Program."""
    ob = state.option_base if state.option_base is not None else 0
    dims, cur_ob = [], 0  # BASIC default at program top
    for a in reversed(state.arrs):
        if ob == 1 and set(a["lo"]) == {0} and a.get("varacc") and not a.get("subful"):
            # lo=0 record with SUB-FREE variable access in an OB1 program:
            # only the OB0-PLAIN form compiles that shape --
            # explicit `0:hi` is record-identical but sub-ful (t1_mix3).
            # OPTION BASE may be re-issued mid-block (witness t1_ob3).
            want, bounds = 0, tuple(a["hi"])
        else:
            want = ob if ob == 1 else cur_ob
            bounds = tuple(
                h if lo == ob else (lo, h) for lo, h in zip(a["lo"], a["hi"])
            )
        if want != cur_ob:
            dims.append(ir.OptionBase(want))
            cur_ob = want
        dims.append(ir.Dim(a["name"], bounds))
    if state.option_base == 1 and cur_ob != 1:  # runtime DIMs witness OB1
        dims.append(ir.OptionBase(1))  # (lo-store order)
    ins = 0  # static DIMs follow any proc definitions
    while ins < len(state.stmts) and isinstance(
        state.stmts[ins], (ir.SubDef, ir.DefFn)
    ):
        ins += 1
    state.stmts[ins:ins] = dims
    state.addrs[ins:ins] = [None] * len(dims)
    # DATA is codeless: re-emit as a block at the very top. Recover the
    # pool only when the program consumes it (a READ/RESTORE) so a string-literal
    # pool frame is never misread as DATA. Split into DATA stmts at item 0 and at
    # every RESTORE <line> target item index, so the target maps to a real stmt.
    if any(isinstance(s, (ir.Read, ir.Restore)) for s in state.stmts):
        items = _read_data_pool(state.exe)
        if items:
            splits = {0} | {
                s.target
                for s in state.stmts
                if isinstance(s, ir.Restore) and isinstance(s.target, int)
            }
            data_block, item_to_stmt, pending = [], {}, []
            for i, it in enumerate(items):
                if i in splits:
                    if pending:
                        data_block.append(ir.Data(tuple(pending)))
                        pending = []
                    item_to_stmt[i] = len(data_block)  # this item opens block[len]
                pending.append(it)
            if pending:
                data_block.append(ir.Data(tuple(pending)))
            state.stmts[0:0] = data_block  # prepend: block pos = final index
            state.addrs[0:0] = [None] * len(data_block)
            state.stmts[:] = [
                (
                    ir.Restore(item_to_stmt[s.target])
                    if isinstance(s, ir.Restore) and isinstance(s.target, int)
                    else s
                )
                for s in state.stmts
            ]
    # EXIT FOR/LOOP folds (Task 3.1): rewrite the early-exit GOTO to the loop
    # exit, then fold `IF c THEN <skip>` + EXIT into `IF negate(c) THEN EXIT`.
    _apply_exit_folds(state.stmts, state.addrs, state.exit_folds)
    state.stmts[:], state.addrs[:] = _fold_if(
        state.stmts, state.addrs
    )  # multi-line IF blocks (Task 3.3)
    fixed_lines = None
    trace_partial: dict[int, int] = {}
    _top_addrs = {a for a in state.addrs if a is not None}
    orphans = {a: l for a, l in state.trace_tbl.items() if a not in _top_addrs}
    traced_idx: set[int] = set()
    # A fully-traced block's inner-body hooks are also "orphans" (folded away),
    # but the normal path consumes them via hook_seq physical-line counting.
    # The mid-body-TROFF signature is narrower: the REGION-END hook itself (the
    # last, highest-address hook) stamps a body statement rather than a
    # top-level statement start (t1_troffin) -- there is no post-block TROFF.
    if state.trace_tbl and orphans and max(state.trace_tbl) not in _top_addrs:
        # Region ends INSIDE a block body: the TROFF hook stamps a body
        # statement, so it never surfaces as a top-level addr (t1_troffin).
        state.stmts[:], state.addrs[:], fixed_lines, trace_partial = (
            _lift_midblock_troff(
                state.stmts,
                state.addrs,
                state.trace_tbl,
                orphans,
                state.stmt_addr,
                state.hook_seq,
            )
        )
        traced_idx = set(trace_partial)  # the block; floor pins are not traced
    elif state.trace_tbl:
        # TRON/TROFF lift: each hook paired with the statement that kept cur
        # on it. TRON/TROFF themselves compile to no code, so both are
        # synthesized per contiguous hook run (t1_tron2r2 has two): TRON
        # before the run's first statement, and -- because TROFF's own line
        # still carries a hook -- when unhooked statements follow the run,
        # its LAST hook is TROFF's and the statement paired with it is
        # really the first post-region statement (witnessed t1_tron2). A run
        # reaching program end keeps the hook line on its last statement
        # (TROFF-before-END is byte-invisible, t1_tron_troff).
        hooked = [i for i, a in enumerate(state.addrs) if a in state.trace_tbl]
        if not hooked:
            raise ValueError("trace hooks present but paired with no statement")
        runs: list[Any] = []
        for i in hooked:
            if runs and i == runs[-1][-1] + 1:
                runs[-1].append(i)
            else:
                runs.append([i])
        hookline = {i: state.trace_tbl[state.addrs[i]] for i in hooked}
        starts = {r[0] for r in runs}
        demote = {r[-1] for r in runs if r[-1] < len(state.stmts) - 1}
        new_s, new_a, fixed_lines = [], [], {}
        for i, (s, a) in enumerate(zip(state.stmts, state.addrs)):
            if i in starts:
                new_s.append(ir.Tron())  # TRON's own line is free
                new_a.append(None)
            if i in demote:
                new_s.append(ir.Troff())  # TROFF takes the hook line;
                new_a.append(None)  # the demoted statement's own
                fixed_lines[len(new_s) - 1] = hookline.pop(i)  # line is free
            new_s.append(s)
            new_a.append(a)
            if i in hookline:
                fixed_lines[len(new_s) - 1] = hookline[i]
        state.stmts[:], state.addrs[:] = new_s, new_a
        traced_idx = set(fixed_lines)
    # $EVENT regions: when trapping is in play the compiler emits a CC
    # poll hook before EVERY statement; $EVENT OFF..ON suppresses them
    # for a run of statements (witnessed t1_evreg), or everywhere when OFF
    # precedes all statements (t1_evoff -- RETURN stays CB either way).
    # Synthesize a pragma line at each hooked/unhooked transition.
    ev_metas = []
    if state.cc_hooks or any(o[1] in ("on_trap", "trap_ctl") for o in state.ops):
        on = True  # compiler default: $EVENT ON
        for i, a in enumerate(state.addrs):
            if a is None:  # synthesized stmt: state persists
                continue
            if (a in state.cc_hooks) != on:
                on = not on
                ev_metas.append((i, f"$EVENT {'ON' if on else 'OFF'}"))
    if state.discard_strs:
        raise ValueError(
            "pooled string literals left unattached after the "
            "fre_str sites were served (unsupported shape)"
        )
    prog = Program(canonical_rename(_resolve_targets(state.stmts, state.addrs)))
    prog.metas = tuple((0, m) for m in state.metas) + tuple(ev_metas)
    prog.toggles = state.toggles
    if fixed_lines is not None:
        prog.lines = _fill_lines(fixed_lines, len(prog))
        # emit0 numbers one physical line per hook inside traced
        # statements (block bodies in a TRON region carry their own
        # hooks -- t1_tronif/t1_troncase)
        prog.hook_seq = tuple(state.hook_seq)
        prog.traced = tuple(sorted(traced_idx))
        # A block whose region ends mid-body traces only a prefix of its
        # physical lines (t1_troffin): {stmt index -> traced line count}.
        prog.trace_partial = dict(trace_partial)
    if any(
        o[1] in ("resume_pre", "on_error", "error_stmt")
        or (o[1] == "movax_m" and o[2] in (0x72, 0x74))
        for o in state.ops
    ):
        table = _line_table(
            state.exe,
            state.start,
            state.addrs,
            addr,
            extra_offs={a + 4 - state.start for a in state.trace_tbl},
        )
        if fixed_lines is not None and table is not None:
            # TRON + a line-needing error construct (bare RESUME, ERL):
            # the table coexists with the hooks (t1_tronres), keyed by
            # POST-hook offsets, and stores REAL lines -- including the
            # true line of the statement demoted by the TROFF pairing
            # (whose hook keeps TROFF's line). Table lines win; the
            # synthesized TROFF keeps its hook line; TRON's is filled.
            real = {}
            for i, a in enumerate(state.addrs):
                if a is None:
                    continue
                off = a - state.start
                line = table.get(off, table.get(off + 4))
                if line is None:
                    raise ValueError(
                        "TRON-region statement missing from the error-trap "
                        "line table (unsupported shape)"
                    )
                real[i] = line
            real.update(
                {i: ln for i, ln in fixed_lines.items() if state.addrs[i] is None}
            )  # the demoted-TROFF pairing
            prog.lines = _fill_lines(real, len(prog))
        elif table is not None:
            try:
                prog.lines = [table[a - state.start] for a in state.addrs]
            except (KeyError, TypeError):
                raise ValueError(
                    "error-trap line table present but statements don't map "
                    "1:1 to its entries (multi-statement lines unsupported)"
                )
    return prog


def fp_dispatch(state: DecodeState, op, addr, kind) -> None:
    """FP-stack + control-flow instruction dispatch (fld/fst/fadd/.../fcomp/jcc/
    jmp/call/run/jmps + unhandled-op guard). Falls through to the default k-advance;
    branches that self-advanced return early."""
    if kind == "fld1":
        state.stack.append(ir.Lit(1))
    elif kind == "fldz":
        state.stack.append(ir.Lit(0))
    elif kind == "fild":
        if op[2] == 0x2C:
            raise ValueError(f"FILD [002C] without a bridge at {addr:#x}")
        if op[2] in state.lay["scalars"]:
            state.stack.append(state.loc(op[2]))  # integer variable read
        else:
            state.stack.append(state.pool_lit(op[2]))
    elif kind == "fld":
        state.stack.append(state.fpval(op[2]))
    elif kind == "fld64":  # m64 load: double var or pooled f64
        state.stack.append(state.fpval64(op[2]))
    elif kind == "fstp64":  # m64 store: double var assign
        v = state.stack.pop()
        if v is _FREAD:
            state._fread_target(state.loc(op[2]))
        elif v is _READDATA:
            state._readdata_target(state.loc(op[2]))
        else:
            state.put(ir.Assign(state.loc(op[2]), v), state.cur)
        state.cur = None
    elif kind == "fold64":  # m64 arithmetic, mem LEFT
        state.stack.append(_orient(op[2], state.fpval64(op[3]), state.stack.pop()))
    elif kind == "fold_n64":  # m64 non-R: mem RIGHT
        top = state.stack.pop()
        if isinstance(top, ir.BinOp) and _PREC[top.op] < _PREC[op[2]]:
            top = ir.Group(top)
        state.stack.append(ir.BinOp(op[2], top, state.fpval64(op[3])))
    elif kind == "fild32":  # m32 int load: long var or pooled i32
        if op[2] == 0x6E:  # runtime dword cell [006E]: ERADR
            state.stack.append(ir.Nullary("ERADR"))
        else:
            try:
                state.stack.append(state.loc(op[2]))
            except ValueError:
                state.stack.append(state.pool_lit32(op[2]))
    elif kind == "fistp32":  # m32 int store: long var assign
        v = state.stack.pop()
        if v is _FREAD:
            state._fread_target(state.loc(op[2]))
        elif v is _READDATA:
            state._readdata_target(state.loc(op[2]))
        else:
            state.put(ir.Assign(state.loc(op[2]), v), state.cur)
        state.cur = None
    elif kind == "ifold32":  # m32 long arithmetic, mem LEFT
        try:
            mem = state.loc(op[3])
        except ValueError:
            mem = state.pool_lit32(op[3])
        state.stack.append(_orient(op[2], mem, state.stack.pop()))
    elif kind == "frndint":  # FRNDINT = CLNG intrinsic
        state.stack.append(ir.Call("CLNG", (state.stack.pop(),)))
    elif kind == "strfn":  # string-result intrinsic
        name = op[2]
        if name in ("CHR$", "SPACE$", "MKI$"):  # integer arg in ax
            args = (state.ax,)
            state.ax = None
        elif name in ("LEFT$", "RIGHT$"):  # string on sstack, count in ax
            n = state.ax
            state.ax = None
            args = (state.sstack.pop(), n)
        elif name == "MID$":  # s$ on sstack, start in bx, len in ax
            ln = state.ax
            state.ax = None
            state.start = state.bx
            state.bx = None
            args = (state.sstack.pop(), state.start, ln)
        elif name == "STRING$":  # n in bx (shuttled), ch in ax
            ch = state.ax
            state.ax = None
            n = state.bx
            state.bx = None
            args = (n, ch)
        elif name in ("INKEY$", "DATE$", "TIME$"):  # zero-arg: bare keyword
            state.sstack.append(ir.Nullary(name))
            state.k += 1
            return
        elif name in ("UCASE$", "LCASE$"):  # string arg via sstack
            args = (state.sstack.pop(),)
        else:  # STR$/HEX$/OCT$/BIN$/MKL$/MKS$/MKD$:
            args = (state.stack.pop(),)  # numeric arg via the FP stack
        state.sstack.append(ir.Call(name, args))
    elif kind == "str2num":  # string-arg numeric intrinsic
        if op[2] == "INSTR":
            sub = state.sstack.pop()  # needle pushed last
            hay = state.sstack.pop()
            call = ir.Call("INSTR", (hay, sub))
        else:
            call = ir.Call(op[2], (state.sstack.pop(),))
        if op[2] in ("VAL", "CVS", "CVD", "CVL"):
            state.stack.append(call)  # result on the FP stack
        else:
            state.ax = call  # ASC/LEN/INSTR/CVI: result in ax
    elif kind == "fchs":
        state.stack.append(ir.Neg(state.stack.pop()))
    elif kind == "fabs":
        state.stack.append(ir.Call("ABS", (state.stack.pop(),)))
    elif kind == "fsqrt":
        state.stack.append(ir.Call("SQR", (state.stack.pop(),)))
    elif kind == "fn":  # runtime intrinsic
        state.stack.append(ir.Call(op[2], (state.stack.pop(),)))
    elif kind == "fn_ax":  # ax-returning intrinsic
        state.ax = ir.Call(op[2], (state.stack.pop(),))
    elif kind == "fn_ax_ax":  # ax-arg ax-returning (REG(n))
        state.ax = ir.Call(op[2], (state.ax,))
    elif kind == "fn_ax0":  # zero-arg ax-returning; POS/PLAY
        state.ax = (
            ir.Call(op[2], (ir.Lit(0),))  # keep their required dummy args
            if op[2] in ("POS", "PLAY")
            else ir.Nullary(op[2])
        )
    elif kind == "fn_fp0":  # zero-arg FP-returning
        state.stack.append(ir.Nullary(op[2]))
    elif kind == "fn_axfp":  # ax-arg, FP-stack-returning (FRE(n))
        state.stack.append(ir.Call(op[2], (state.ax,)))
        state.ax = None
    elif kind == "fre_str":  # FRE(s$): the operand compiles to
        state.stack.append(
            ir.Call(
                "FRE",  # nothing -- variables render as
                (
                    (
                        state.discard_strs.pop(0)
                        if state.discard_strs  # FRE(""), pooled
                        else ir.StrLit("")
                    ),
                ),
            )
        )  # literals are re-attached here
    elif kind == "pmap":  # PMAP(x, n): x FP stack, n ax
        state.stack.append(ir.Call("PMAP", (state.stack.pop(), state.ax)))
        state.ax = None
    elif kind == "movaxds":  # mov ax,ds: VARSEG of a DGROUP var;
        state.ax = ir.VarSeg()  # rendered against the assign target
    elif kind == "fn_screen":  # SCREEN(row, col): bx, ax
        state.ax = ir.Call("SCREEN", (state.bx, state.ax))
        state.bx = None
    elif kind == "fn_ax2":  # two-FP-arg ax intrinsic (POINT)
        y = state.stack.pop()
        x = state.stack.pop()
        state.ax = ir.Call(op[2], (x, y))
    elif kind == "popop":
        last = state.stack.pop()  # last-pushed is the textual LEFT
        first = state.stack.pop()  # (R-form FSUBRP: st1=st0-st1, and
        state.stack.append(ir.BinOp(op[2], _grp(last), _grp(first)))  # R-first
    elif kind == "popop_n":  # non-R: first-pushed is LEFT
        rhs = state.stack.pop()
        lhs = state.stack.pop()
        # lhs was built as a fold chain (no outer group) -- leaving it bare lets
        # TB evaluate it left-first and emit FDIVP/FSUBP.
        # Wrapping lhs in _grp would cause TB to reorder evaluation (right-first)
        # and emit the R-form FDIVRP/FSUBRP instead.
        state.stack.append(ir.BinOp(op[2], lhs, _grp(rhs)))
    elif kind == "fold":
        state.stack.append(_orient(op[2], state.fpval(op[3]), state.stack.pop()))
    elif kind == "fold_n":  # non-R: mem is the RIGHT operand
        top = state.stack.pop()
        if isinstance(top, ir.BinOp) and _PREC[top.op] < _PREC[op[2]]:
            top = ir.Group(top)  # (B + C) / D: parens required
        state.stack.append(ir.BinOp(op[2], top, state.fpval(op[3])))
    elif kind == "ifold_n":
        right = (
            state.loc(op[3]) if op[3] in state.lay["scalars"] else state.pool_lit(op[3])
        )
        top = state.stack.pop()
        if isinstance(top, ir.BinOp) and _PREC[top.op] < _PREC[op[2]]:
            top = ir.Group(top)
        state.stack.append(ir.BinOp(op[2], top, right))
    elif kind == "ifold":  # int var or pool literal
        mem = (
            state.loc(op[3]) if op[3] in state.lay["scalars"] else state.pool_lit(op[3])
        )
        state.stack.append(_orient(op[2], mem, state.stack.pop()))
    elif kind == "fstp" and op[2] in (0x88, 0x94, 0xA0, 0xAC):
        state.color_cells[op[2]] = state.stack.pop()  # WINDOW world-coord cell (FP leg)
    elif kind == "fstp":
        v = state.stack.pop()
        # Implicit-single narrowing: a pooled f64 literal stored to a width-4
        # non-long slot was an unsuffixed source literal (`A = 1.5`) -- render
        # it plain (a `#` or `!` suffix would not be byte-faithful).
        if (
            isinstance(v, ir.DblLit)
            and state.lay["scalars"].get(op[2]) == 4
            and op[2] not in state.lay["long_slots"]
        ):
            v = ir.SingleLit(v.value)
        if v is _FREAD:  # INPUT# near numeric target
            state._fread_target(state.loc(op[2]))
        elif v is _READDATA:  # READ numeric target
            state._readdata_target(state.loc(op[2]))
        else:
            state.put(ir.Assign(state.loc(op[2]), v), state.cur)
        state.cur = None
    elif kind == "fcomp":
        state.pend_cmp = (state.fpval(op[2]), state.stack.pop())
    elif kind == "fstsw":
        pass
    elif kind == "jcc":
        cc, t = op[2], op[3]
        nxt = state.ops[state.k + 1] if state.k + 1 < len(state.ops) else None
        if state.pend_cmp and nxt and nxt[1] == "jmp" and t == nxt[0] + 3:
            if cc not in _JCC_RELOP:
                raise ValueError(f"unhandled IF jcc {cc:02x} at {addr:#x}")
            lhs, rhs = state.pend_cmp
            state.pend_cmp = None
            state.put(
                ir.IfGoto(ir.RelOp(_JCC_RELOP[cc], lhs, rhs), ("addr", nxt[2])),
                state.cur,
            )
            state.cur = None
            state.k += 2
            return
        if state.pend_cmp and cc in _JCC_RELOP_TRUE:  # direct conditional GOTO (taken =
            lhs, rhs = state.pend_cmp  # THEN): IF cond THEN <line>, short
            state.pend_cmp = None  # jcc with no skip-jmp (witnessed zz_godo)
            state.put(
                ir.IfGoto(ir.RelOp(_JCC_RELOP_TRUE[cc], lhs, rhs), ("addr", t)),
                state.cur,
            )
            state.cur = None
            state.k += 1
            return
        raise ValueError(f"unhandled jcc {cc:02x} at {addr:#x}")
    elif kind == "jmp":
        t = op[2]
        frame = state.proc_frame if state.proc_frame is not None else state.fn_frame
        cmp_at_t = next((o for o in state.ops if o[0] == t), None)
        if _is_for_header(state.stmts, state.vdisp):
            lim_s, stp_s, init_s = state.stmts[-3:]
            del state.stmts[-3:]
            a = state.addrs[-3]
            del state.addrs[-3:]
            v = init_s.target
            state.put(ir.For(v, init_s.value, lim_s.value, stp_s.value), a)
            state.fors.append(
                {
                    "v": state.vdisp(v),
                    "test": t,
                    "body": state.ops[state.k + 1][0]
                    if state.k + 1 < len(state.ops)
                    else None,
                }
            )
        elif (
            cmp_at_t is not None
            and cmp_at_t[1] == "cmp_mi8"
            and state.stmts
            and isinstance(state.stmts[-1], ir.Assign)
            and isinstance(state.stmts[-1].target, ir.Var)
            and isinstance(state.stmts[-1].value, ir.Lit)
            and cmp_at_t[2] == state.vdisp(state.stmts[-1].target)
        ):
            # Integer FOR header: `I% = init; jmp cmp_addr` where the op at the
            # target is `cmp word [I%], limit`. The step is always 1 (inc_m).
            init_s = state.stmts.pop()
            a = state.addrs.pop()
            state.put(
                ir.For(init_s.target, init_s.value, ir.Lit(cmp_at_t[3]), ir.Lit(1)),
                a,
            )
            state.fors.append(
                {
                    "v": cmp_at_t[2],
                    "test": t,
                    "body": state.ops[state.k + 1][0]
                    if state.k + 1 < len(state.ops)
                    else None,
                }
            )
        elif (
            frame is not None and t == frame["exit"]
        ):  # jmp to ProcRet/FnRet = EXIT SUB/DEF
            exit_stmt = ir.ExitSub() if state.proc_frame is not None else ir.ExitDef()
            if (
                state.stmts
                and isinstance(state.stmts[-1], ir.IfGoto)
                and isinstance(state.stmts[-1].target, tuple)
            ):
                state.exit_folds.append((exit_stmt, state.stmts[-1].target[1], t))
            state.put(ir.Goto(("addr", t)), state.cur)
        else:
            state.put(ir.Goto(("addr", t)), state.cur)
        state.cur = None
    elif kind == "call":
        state.put(ir.Gosub(("addr", op[2])), state.cur)
        state.cur = None
    elif kind in ("ret", "retf"):  # retf = RETURN under event trapping
        state.put(ir.Return(), state.cur)
        state.cur = None
    elif kind == "run":
        state.put(ir.Run(), state.cur)
        state.cur = None
    elif kind == "jmps":
        nxt = state.ops[state.k + 1] if state.k + 1 < len(state.ops) else None
        if (
            state.dos and op[2] == state.dos[-1]["test"]
        ):  # head-test DO ... LOOP back-edge
            f = state.dos.pop()
            if nxt is None or nxt[0] != f["exit"]:
                raise ValueError(f"LOOP exit mismatch at {addr:#x}")
            state.put(ir.Loop(None), state.cur)
        elif (
            state.whiles and op[2] == state.whiles[-1]["test"]
        ):  # legacy WHILE ... WEND
            f = state.whiles.pop()
            if nxt is None or nxt[0] != f["exit"]:
                raise ValueError(f"WEND exit mismatch at {addr:#x}")
            state.put(ir.Wend(), state.cur)
        elif op[2] < addr and op[2] in state.addrs:  # bare backward jmps = infinite DO
            idx = state.addrs.index(op[2])  # splice `DO` before the body start
            state.stmts.insert(idx, ir.Do(None))
            state.addrs.insert(idx, None)
            state.put(ir.Loop(None), state.cur)
            # EXIT LOOP: a GOTO past the LOOP (to nxt) is an exit; the conditional that
            # skips it jumps to the LOOP back-edge (this jmps' addr). Fold at epilogue.
            if nxt is not None:
                state.exit_folds.append((ir.ExitLoop(), addr, nxt[0]))
        else:
            raise ValueError(f"unhandled jmp short at {addr:#x}")
        state.cur = None
    else:
        raise ValueError(f"unhandled op {kind} at {addr:#x}")
    state.k += 1


def decode_user_code(exe: bytes) -> list[Any]:
    """Decode from the prologue to (and including) END. Returns typed IR statements with
    canonical variable names and statement-index jump targets."""
    state = DecodeState()
    state.exe = exe
    state.start, state.dia = find_prologue(exe)
    state.metas = _meta_stmts(
        exe, state.start
    )  # read now: `start` is rebound downstream
    state.toggles = _toggles(exe, state.start)
    state.commits = set()
    state.ops = _scan(exe, state.start, state.dia, state.commits)
    # TRON trace hooks are per-LINE position markers, not statements: fold each
    # out of the op stream, re-stamping the FOLLOWING op with the hook's address
    # (uniform "hooks keep cur" semantics -- statement starts land on the hook,
    # so jump targets and the hook+4 alias behave as before) so that multi-op
    # recognizers (IF folds, SELECT CASE) see uninterrupted patterns
    # (t1_tronif/t1_troncase). Consecutive hooks are code-less source lines
    # (END IF): they share the stamp address; trace_tbl keeps the LAST line for
    # the statement pin and hook_seq keeps ALL lines in order -- emit0 numbers
    # one physical line per hook inside traced statements.
    state.trace_tbl = {}  # hook stamp addr -> line number (last wins)
    state.hook_seq = []  # every hook line, in address order
    if any(o[1] == "trace_hook" for o in state.ops):
        ops2, pend_hook, alias = [], None, {}
        for o in state.ops:
            if o[1] == "trace_hook":
                h = o[0] if pend_hook is None else pend_hook
                state.trace_tbl[h] = o[2]
                state.hook_seq.append(o[2])
                alias[o[0] + 4] = h  # a jump target past this hook -> its stamp
                pend_hook = h
            else:
                if pend_hook is not None:
                    o = (pend_hook,) + o[1:]
                    pend_hook = None
                ops2.append(o)
        # Compiled jump targets point PAST a line's trace hook at its code
        # (t1_tronerr RESUME n, t1_tronif else-skip, t1_troncase END SELECT);
        # normalize them onto the stamps so every downstream address compare
        # (folds, SELECT machinery, target resolution) is hook-blind. Plain
        # GOTO targets the hook itself (t1_trongoto) and passes through.
        state.ops = []
        for o in ops2:
            if o[1] in ("jmp", "jmps") or (o[1] == "on_error" and o[2] is not None):
                o = (o[0], o[1], alias.get(o[2], o[2]))
            elif o[1] in ("jcc", "on_trap"):
                o = o[:3] + (alias.get(o[3], o[3]),)
            state.ops.append(o)
    state.lay = _layout(exe, state.ops)
    state.ds = state.lay["ds"]
    state.dsd = (
        state.ds - state.lay["delta"]
    )  # file base for pool/descriptor/string reads
    state.arrs = state.lay["arrs"]  # static arrays (unified slot records)
    # Unified slot registry for the far/near index machine: static slots prefilled
    # from their records; runtime blocks register at their DIM bracket.
    state.slot_info = {
        state.lay["var_base"] + ARR_BLOCK * i: a for i, a in enumerate(state.arrs)
    }
    for a in state.arrs:
        if a["str"] and not a["name"].endswith("$"):
            a["name"] += "$"  # element type from the record
        if a["long"] and not a["name"].endswith("&"):
            a["name"] += "&"  # long-integer arrays render with `&`
        if a.get("int") and not a["name"].endswith("%"):
            a["name"] += "%"  # integer arrays (type 00, esz 2) render with `%`
    state.stack = []  # the emulated FP stack, as ir Expr nodes
    state.stmts = []
    state.addrs = []  # addrs[k] = first-op address of stmts[k]
    state.stmt_addr = {}  # id(stmt) -> its op address, retained across the inline
    # fold (which drops body addrs) so the TRON lift can find
    # a region that ends INSIDE a block body (t1_troffin)
    state.cur = None  # start address of the statement being built
    state.pend_cmp = None  # (lhs_expr, rhs_expr) from FLD y; FCOMP [x]
    state.fors = []  # open FOR frames
    state.whiles = []  # open WHILE frames
    state.dos = []  # open head-test DO frames (DO WHILE/UNTIL ... LOOP)
    state.exit_folds = []  # (exit_stmt, skip_addr, exit_addr): EXIT FOR/LOOP folds
    state.cases = []  # open SELECT CASE frames (Task 3.4)
    state.ax = None  # the integer accumulator, as an ir Expr
    state.bx = None  # LOCATE's row register / int right operand
    state.dx = None  # IMP's left operand register
    state.pend_icmp = None  # (lhs, rhs) from cmp ax,[m]: relational value
    state.cc_hooks = set()  # CC event-poll hook addrs ($EVENT regions)
    state.cint_round = False  # fistp[2C]..fild[2C] round-trip = CINT(x)
    state.color_cells = {}  # pending COLOR stores: cell disp -> Lit
    state.sstack = []  # the string operand stack
    state.pend_input = None  # (prompt Expr|None, flags) awaiting its read call
    state.pend_fnum = None  # file number from the [0060] cell
    state.dim_frame = None  # open runtime-DIM bracket
    state.prev_dim_end = None  # last allocate's addr: comma-chain test
    state.r_arrs = {}  # block disp -> runtime array info
    state.option_base = None  # 0/1 from DIM lower-bound cells
    state.pend_es = None  # block disp loaded into ES (far access)
    state.cx = None  # 2nd-level index stash / WAIT and-mask
    state.si = None  # element-index register (raw index / idx token)
    state.bchk_subs = []  # Bounds: pending non-final subscripts (F3.5)
    state.pend_bool = None  # compound-IF first term awaiting its tail
    state.pend_print = None  # open PRINT item chain
    state.pend_using = None  # open PRINT USING value chain
    state.pend_filein = None  # open INPUT# target chain
    state.pend_dataread = None  # open READ target chain
    state.ifs = []  # open inline-IF bodies
    state.has_procs = any(
        o[1] in ("proc_enter", "fn_ret") for o in state.ops
    )  # def region present
    state.proc_names = {}  # proc entry addr -> synthesized name (SUB1.., FNFN1..)
    # open SUB body {entry, idx} (idx into stmts) / open DEF FN body {.., result, max_off}
    state.proc_frame = None
    state.fn_frame = None
    state.fn_args = {}  # staged FN-call args: bp_off -> Expr (offset-ordered)
    state.main_start = None  # def-region end = entry-jmp target
    state.nsub = 0  # SUB counter (entry-offset order)
    state.nfn = 0  # DEF FN counter (entry-offset order)
    state.pend_arg = None  # by-ref param bp_off from arg_ref (les si,[bp+N])
    state.pend_args = []  # accumulated CALL args, drained by far_call
    state.sp_save_cell = None  # cell holding saved SP (literal-arg staging)
    state.proc_str_offs = (
        set()
    )  # bp_offs the open proc reads as strings (arg_ref;far_spush)

    # String-space base: ss_base = align16(pool end), but the pool can
    # hold words the code never references (LOCATE/COLOR arg literals compile to
    # immediates yet are still pooled), so a reference-based estimate undershoots.
    # Anchor it instead on the char record itself, which is bracketed on BOTH sides by
    # the word (sum_of_string_lens | 0x8000) with 4 zero bytes after the leading one:
    # ds+ss_base+0x10: <hdr> 00 00 00 00 <chars...> <hdr>.
    state.ss_base = None
    # Pooled literal descriptors: movsi targets that aren't var slots, plus INPUT /
    # LINE INPUT prompt words (excluding the resident empty-string desc and
    # constant far-element offsets).
    state.desc_disps = sorted(
        (
            {
                state.ops[i][2]
                for i in range(len(state.ops))
                if state.ops[i][1] == "movsi"
                and state.ops[i][2]
                >= VAR_BASE  # sub-VAR_BASE = scratch (SELECT CASE str temp)
                and not (
                    i + 1 < len(state.ops)
                    and state.ops[i + 1][1]
                    in ("far_spush", "far_strassign", "add_si_sp")
                )
            }
            - set(state.lay["scalars"])
            - set(state.lay["rt_blocks"])
            - set(state.slot_info)
        )  # GET/PUT blit array-slot pushes (t1_getput)
        | {
            o[2]
            for o in state.ops
            if o[1] in ("input", "line_input") and o[2] != state.lay["pool_base"] - 4
        }
    )
    # Discarded string literals (FRE(s$), witnessed t1_fres): the argument compiles to
    # NOTHING -- bare ED 16 whatever the operand -- but a LITERAL operand still pools
    # (descriptor + chars), so summing only code-referenced descriptors undershoots
    # `total`. Walk the descriptor table itself instead: it starts at the resident
    # empty-string desc (pool_base-4) and runs ascending with contiguous
    # char pointers. Literals pool in REVERSE source order (witnessed t1_fres2:
    # "Z","AA","BBB" in source lands as BBB/AA/Z), so the unreferenced ones are
    # queued reversed and handed to fre_str sites in code order.
    state.discard_strs = []
    state.have_fre = any(o[1] == "fre_str" for o in state.ops)
    if state.desc_disps or state.have_fre:
        all_descs = []
        d = state.lay["pool_base"] - 4
        w0, expect = struct.unpack_from("<HH", exe, state.dsd + d)
        if w0 == 0x8000:  # resident empty desc anchors the walk
            d += 4
            while True:
                w0, ptr = struct.unpack_from("<HH", exe, state.dsd + d)
                if not w0 & 0x8000 or ptr != expect:
                    break
                all_descs.append((d, w0 & 0x7FFF, ptr))
                expect = ptr + (w0 & 0x7FFF)
                d += 4
        if all_descs:
            total = sum(ln for _, ln, _ in all_descs)
        else:  # no walkable table: referenced sum as before
            total = sum(
                struct.unpack_from("<H", exe, state.dsd + d)[0] & 0x7FFF
                for d in state.desc_disps
            )
        hdr = struct.pack("<H", 0x8000 | total)
        lo = (state.lay["pool_base"] + 15) & ~15
        for cand in range(lo, lo + 0x400, 16):
            pos = state.dsd + cand + 0x10
            if (
                exe[pos : pos + 2] == hdr
                and exe[pos + 2 : pos + 6] == b"\x00\x00\x00\x00"
                and exe[pos + 6 + total : pos + 8 + total] == hdr
            ):
                state.ss_base = cand
                break
        else:
            raise ValueError("string char record not found")
        unref = [(ln, ptr) for d, ln, ptr in all_descs if d not in state.desc_disps]
        if unref:
            if not state.have_fre:
                raise ValueError(
                    "unreferenced pooled string literals without a "
                    "FRE(s$) site to carry them (unsupported)"
                )
            state.discard_strs = [
                ir.StrLit(
                    exe[
                        state.dsd + state.ss_base + ptr : state.dsd
                        + state.ss_base
                        + ptr
                        + ln
                    ].decode("latin-1")
                )
                for ln, ptr in reversed(unref)
            ]

    state.k = 0
    while state.k < len(state.ops):
        op = state.ops[state.k]
        addr, kind = op[0], op[1]
        if select_case.step(state):
            continue
        while state.ifs and addr == state.ifs[-1]["target"]:  # inline-IF body ends here
            fr = state.ifs.pop()
            state.flush_pending()
            body = tuple(state.stmts[fr["idx"] :])
            if not body:
                raise ValueError(f"empty inline-IF body at {addr:#x}")
            for st, ad in zip(body, state.addrs[fr["idx"] :]):
                if ad is not None:  # retain leaf/body addrs before they drop
                    state.stmt_addr[id(st)] = ad  # (the fold discards addrs[fr.idx:])
            del state.stmts[fr["idx"] :], state.addrs[fr["idx"] :]
            state.stmts.append(ir.IfInline(fr["cond"], body))
            state.addrs.append(fr["start"])
        # --- procedure-region segmentation ---
        if state.has_procs and state.k == 0 and kind == "jmp":
            state.main_start = op[
                2
            ]  # entry jmp over the def region: target = main start
            state.k += 1  # glue, not a GOTO
            continue
        # A DEF FN body has no proc_enter prologue (terminated by fn_ret): the first
        # op in the def region with no open frame opens one.
        if (
            state.has_procs
            and state.fn_frame is None
            and state.proc_frame is None
            and state.main_start is not None
            and addr < state.main_start
            and kind != "proc_enter"
        ):
            state.fn_frame = {
                "entry": addr,
                "idx": len(state.stmts),
                "result": None,
                "max_off": 0,
                "exit": next(o[0] for o in state.ops[state.k :] if o[1] == "fn_ret"),
                "block": False,
            }
            state.cur = None  # fall through to lift this op into the body
        if kind == "proc_enter":
            state.flush_pending()
            state.proc_frame = {
                "entry": addr,
                "idx": len(state.stmts),
                "exit": next(o[0] for o in state.ops[state.k :] if o[1] == "proc_ret"),
            }
            state.proc_str_offs = set()
            state.cur = None
            state.k += 1
            continue
        if kind == "proc_ret":
            assert state.proc_frame is not None  # proc_ret only closes an open SUB body
            state.flush_pending()
            _apply_exit_folds(
                state.stmts, state.addrs, state.exit_folds
            )  # EXIT SUB fold (Task 3.5), body-local
            state.exit_folds.clear()
            body = tuple(state.stmts[state.proc_frame["idx"] :])
            del (
                state.stmts[state.proc_frame["idx"] :],
                state.addrs[state.proc_frame["idx"] :],
            )
            state.nsub += 1
            name = f"SUB{state.nsub}"
            state.proc_names[state.proc_frame["entry"]] = name
            nparams = op[2] // 4  # retf pop bytes = 4 x nargs
            params = tuple(
                f"P{off:02X}$" if off in state.proc_str_offs else f"P{off:02X}"
                for off in (6 + 4 * (nparams - 1 - i) for i in range(nparams))
            )
            state.stmts.append(ir.SubDef(name, params, body))
            state.addrs.append(None)  # a SUB definition is never a jump target
            state.proc_frame = None
            state.cur = None
            state.k += 1
            continue
        if handlers.calls(state, op, addr, kind):
            continue
        # --- DEF FN body & value-returning FN call ---
        if kind == "mov_bp_imm":  # [bp+0/2]=0 result-slot init: multi-line DEF FN
            assert state.fn_frame is not None  # only appears inside an open DEF FN body
            state.fn_frame["block"] = True
            state.k += 1
            continue
        if kind == "fn_ret":  # close the open DEF FN body
            assert state.fn_frame is not None  # fn_ret only closes an open DEF FN body
            nparams = (
                state.fn_frame["max_off"] // 4
            )  # P04 = 1, P08 = 2, ... (off 0 = result)
            params = tuple(f"P{4 + 4 * i:02X}" for i in range(nparams))
            state.nfn += 1
            name = f"FNFN{state.nfn}"
            state.proc_names[state.fn_frame["entry"]] = name
            if state.fn_frame["block"]:  # multi-line DEF FN ... END DEF
                _apply_exit_folds(
                    state.stmts, state.addrs, state.exit_folds
                )  # EXIT DEF fold (body-local)
                state.exit_folds.clear()
                body = tuple(state.stmts[state.fn_frame["idx"] :])
                del (
                    state.stmts[state.fn_frame["idx"] :],
                    state.addrs[state.fn_frame["idx"] :],
                )
                state.stmts.append(ir.DefFn(name, params, body, True))
            else:  # single-line DEF FN = expr
                expr = state.fn_frame["result"]
                if expr is None:  # no FSTP [bp+0]: result left on stack
                    expr = state.stack.pop()
                del (
                    state.stmts[state.fn_frame["idx"] :],
                    state.addrs[state.fn_frame["idx"] :],
                )
                state.stmts.append(ir.DefFn(name, params, expr))
            state.addrs.append(None)  # a DEF FN definition is never a jump target
            state.fn_frame = None
            state.cur = None
            state.k += 1
            continue
        if handlers.fp_bp(state, op, addr, kind):
            continue

        if handlers.cargs(state, op, addr, kind):
            continue
        # Literal-arg staging: glue ops carry no source.
        if kind == "mov_mem_sp":  # mov [cell],sp: remember the SP-save cell
            state.sp_save_cell = op[2]
            state.k += 1
            continue
        if handlers.stack_ops(state, op, addr, kind):
            continue

        if handlers.bounds(state, op, addr, kind):
            continue
        if handlers.string_ops(state, op, addr, kind):
            continue
        if (
            kind == "movsi"
            and state.k + 1 < len(state.ops)
            and state.ops[state.k + 1][1] == "add_si_sp"
        ):
            state.k += 1  # mov si,off feeding add si,sp: temp-slot glue
            continue
        if (
            kind == "movm_imm" and op[2] == state.sp_save_cell
        ):  # mov [cell],0: paired SP-save clear
            state.k += 1
            continue
        if handlers.fp_math(state, op, addr, kind):
            continue
        if state.cur is None:
            state.cur = addr
        if (
            state.pend_arg is not None and kind == "far_spush"
        ):  # string by-ref param read
            state.proc_str_offs.add(state.pend_arg)
            state.sstack.append(ir.Var(f"P{state.pend_arg:02X}$"))
            state.pend_arg = None
            state.k += 1
            continue
        if state.pend_arg is not None and kind.endswith("_si"):
            argvar = ir.Var(f"P{state.pend_arg:02X}")
            base = kind[4:] if kind.startswith("far_") else kind  # strip far_ prefix
            if base == "fld_si":
                state.stack.append(argvar)
            elif base == "fstp_si":
                state.put(ir.Assign(argvar, state.stack.pop()), state.cur)
                state.cur = None
            elif base == "fold_si":
                state.stack.append(_orient(op[2], argvar, state.stack.pop()))
            elif base == "fold_n_si":  # mem is RIGHT operand
                top = state.stack.pop()
                if isinstance(top, ir.BinOp) and _PREC[top.op] < _PREC[op[2]]:
                    top = ir.Group(top)
                state.stack.append(ir.BinOp(op[2], top, argvar))
            elif base == "fcomp_si":
                state.pend_cmp = (argvar, state.stack.pop())
            else:
                raise ValueError(f"unhandled by-ref param op {kind} at {addr:#x}")
            state.pend_arg = None
            state.k += 1
            continue
        if kind == "testw" and state.fors and addr == state.fors[-1]["test"]:
            state.k = _lift_next(
                state.ops,
                state.k,
                state.fors,
                state.stmts,
                state.addrs,
                state.exit_folds,
            )
            state.cur = None
            continue
        if kind == "cmp_mi8" and state.fors and addr == state.fors[-1]["test"]:
            # Integer FOR-test guard: the cmp at the open FOR's test address is the
            # integer NEXT template (`inc_m` was consumed; step is always 1).
            f = state.fors[-1]
            if op[2] != f["v"]:
                raise ValueError(f"int NEXT: cmp disp mismatch at {addr:#x}")
            if (
                state.k + 1 >= len(state.ops)
                or state.ops[state.k + 1][1] != "jcc"
                or state.ops[state.k + 1][2] not in (0x7E, 0x76)
                or state.ops[state.k + 1][3] != f["body"]
            ):
                raise ValueError(f"int NEXT: expected JLE/JBE to body at {addr:#x}")
            state.put(ir.NextStmt(state.loc(f["v"])), state.cur)
            state.fors.pop()
            state.cur = None
            state.k += 2
            continue
        if handlers.int_alu(state, op, addr, kind):
            continue
        if kind == "epilogue":
            return _finalize(state, addr)

        if kind == "end":
            state.put(ir.End(), state.cur)
            state.cur = None
            state.k += 1
            continue
        if handlers.movax_family(state, op, addr, kind):
            continue

        if kind == "movax_m":  # int var load (right operand first)
            if op[2] == 0x74:  # runtime cells, not user slots:
                state.ax = ir.Err()
            elif op[2] == 0x72:  # ERR = [0074], ERL = [0072]
                state.ax = ir.Erl()
            else:
                state.ax = state.loc(op[2])
            state.k += 1
            continue
        if handlers.int_bitwise_m(state, op, addr, kind):
            continue

        if kind == "cwd":  # sign-extend ahead of idiv: lift no-op
            state.k += 1
            continue
        if handlers.int_bitwise_bx(state, op, addr, kind):
            continue

        if (
            kind == "movdx"
            and state.k + 2 < len(state.ops)
            and state.ops[state.k + 1][1] == "movesdx"
            and state.ops[state.k + 2][1] == "fn_bound"
        ):  # UBOUND/LBOUND(arr(dim)): slot in
            rec = state.slot_info.get(
                getattr(state.bx, "value", None)
            )  # bx, dim in ax, es = seg
            if rec is None:
                raise ValueError(f"UBOUND/LBOUND array slot unknown at {addr:#x}")
            state.ax = ir.Call(
                state.ops[state.k + 2][2], (ir.ArrayRef(rec["name"], (state.ax,)),)
            )
            state.bx = None
            state.k += 3
            continue
        if kind == "movsi" and (_bj := _blit_at(state.ops, state.k)) is not None:
            rec = state.slot_info.get(op[2])  # (es:)si -> array slot record
            if rec is None:
                raise ValueError(
                    f"GET/PUT blit array slot {op[2]:#06x} unknown at {addr:#x}"
                )
            gp = state.ops[_bj]
            if gp[1] == "get_gfx":
                if gp[2] != 0:
                    raise ValueError(
                        f"GET blit trail byte {gp[2]:02x} at {addr:#x} (unsupported)"
                    )
                y2 = state.stack.pop()
                x2 = state.stack.pop()
                y1 = state.stack.pop()
                x1 = state.stack.pop()
                state.put(ir.GetGfx(x1, y1, x2, y2, rec["name"]), state.cur)
            else:
                if gp[2] not in _PUT_ACTIONS:
                    raise ValueError(
                        f"PUT blit action {gp[2]:02x} at {addr:#x} (unsupported)"
                    )
                y = state.stack.pop()
                x = state.stack.pop()
                state.put(ir.PutGfx(x, y, rec["name"], _PUT_ACTIONS[gp[2]]), state.cur)
            state.cur = None
            state.k = _bj + 1
            continue
        if handlers.timing(state, op, addr, kind):
            continue
        if (
            kind == "movsi"
            and state.k + 3 < len(state.ops)
            and state.ops[state.k + 1][1] == "movdx"
            and state.ops[state.k + 2][1] == "movesdx"
            and state.ops[state.k + 3][1] in ("dim_begin", "dim_end", "erase")
        ):
            block = op[2]  # runtime-DIM bracket
            if state.ops[state.k + 3][1] == "dim_begin":
                state.dim_frame = {"block": block, "cells": {}, "start": state.cur}
            elif state.ops[state.k + 3][1] == "erase":  # ERASE
                if block not in state.r_arrs:
                    raise ValueError(f"ERASE of undimensioned block at {addr:#x}")
                state.put(ir.Erase(state.r_arrs[block]["name"]), state.cur)
            else:
                if state.dim_frame is None or state.dim_frame["block"] != block:
                    raise ValueError(f"unbalanced DIM bracket at {addr:#x}")
                cells = state.dim_frame["cells"]
                rank = 2 if 0x10 in cells else 1
                lows = [cells.get(0x08), cells.get(0x0E)][:rank]
                ups = [cells.get(0x0A), cells.get(0x10)][:rank]
                if any(v is None for v in lows + ups) or len(cells) != 2 * rank:
                    raise ValueError(
                        f"DIM bound cells incomplete at {addr:#x}: {cells}"
                    )
                # Explicit `lo:hi` ranges store lo BEFORE hi (textual order); the
                # default lo under OPTION BASE is patched in AFTER the hi store --
                # cell insertion order is byte-significant (witnessed t1_dimv2).
                # Defaults vote for OPTION BASE.
                order = list(cells)
                expl = [
                    order.index(lo_c) < order.index(hi_c)
                    for lo_c, hi_c in (((0x08, 0x0A), (0x0E, 0x10))[:rank])
                ]
                base_vals = {v.value for d, v in enumerate(lows) if not expl[d]}
                if base_vals - {0, 1}:
                    raise ValueError(
                        f"unexpected DIM lower bounds at {addr:#x}: {lows}"
                    )
                if base_vals:
                    if (
                        state.option_base not in (None, *base_vals)
                        or len(base_vals) != 1
                    ):
                        raise ValueError("inconsistent OPTION BASE across DIMs")
                    state.option_base = base_vals.pop()
                # Runtime slots carry their element type at file time:
                # 0A = string-descriptor elements, so the name is typed from birth.
                is_str = exe[state.ds + block + 2] == 0x0A
                name = (
                    f"V{state.lay['n_static'] + state.lay['rt_blocks'].index(block)}"
                    + ("$" if is_str else "")
                )
                if not all(isinstance(v, ir.Lit) for v in lows):
                    raise ValueError(
                        f"non-literal DIM lower bound at {addr:#x}: {lows}"
                    )
                state.r_arrs[block] = {
                    "name": name,
                    "rank": rank,
                    "str": is_str,
                    "lo": [v.value for v in lows],
                }
                state.slot_info[block] = state.r_arrs[block]
                bounds = tuple(
                    (lo.value, u) if expl[d] else u
                    for d, (lo, u) in enumerate(zip(lows, ups))
                )
                if (
                    state.prev_dim_end is not None
                    and state.prev_dim_end + 3 not in state.commits
                    and isinstance(state.stmts[-1], ir.Dim)
                ):
                    prev = state.stmts[-1]  # no commit after the previous
                    state.stmts[-1] = ir.Dim(
                        prev.name,
                        prev.bounds,  # allocate: same
                        prev.also + ((name, bounds),),
                    )  # comma list
                else:
                    state.put(ir.Dim(name, bounds), state.dim_frame["start"])
                state.prev_dim_end = state.ops[state.k + 3][0]
                state.dim_frame = None
            state.cur = None
            state.k += 4
            continue
        if (
            kind in ("movm_imm", "movm_ax")
            and state.dim_frame is not None
            and state.dim_frame["block"] <= op[2] < state.dim_frame["block"] + ARR_BLOCK
        ):
            val = ir.Lit(op[3]) if kind == "movm_imm" else state.ax
            state.dim_frame["cells"][op[2] - state.dim_frame["block"]] = val
            if kind == "movm_ax":
                state.ax = None
            state.k += 1
            continue
        if kind == "movm_imm" and op[2] < VAR_BASE:  # system cell store
            if op[2] == 0x60:  # file number for OPEN / PRINT#
                state.flush_pending()  # statement boundary
                state.pend_fnum = op[3]
            elif op[2] in (
                0x88,
                0x94,
                0xA0,
                0xAC,  # COLOR fg/bg / VIEW coord cells
                0xB8,
                0xC4,
            ):  # VIEW color/border cells
                state.color_cells[op[2]] = ir.Lit(op[3])
            elif op[2] == 0x1C:  # TB 1.0 DEF SEG = n: inline imm
                state.put(
                    ir.DefSeg(ir.Lit(op[3])), state.cur
                )  # store (1.1 uses EC sub 0x26)
                state.cur = None
            elif op[2] == 0x78:  # DATA read pointer: RESTORE [line]
                imm = op[3]  # 0 = bare RESTORE; N = RESTORE <line>
                if imm == 0:
                    state.put(ir.Restore(None), state.cur)
                elif imm < 0 or imm % 2:
                    raise ValueError(f"bad RESTORE pointer {imm} at {addr:#x}")
                else:
                    state.put(
                        ir.Restore(imm // 2), state.cur
                    )  # raw item index; resolved at epilogue
                state.cur = None
            else:
                raise ValueError(
                    f"store to unknown system cell {op[2]:#x} at {addr:#x}"
                )
            state.k += 1
            continue
        if kind == "movm_ax" and op[2] in (0x88, 0x94, 0xA0, 0xAC):
            state.color_cells[op[2]] = state.ax  # VIEW coord cell (ax leg)
            state.ax = None
            state.k += 1
            continue
        if kind == "movm_ax" and op[2] == 0x60:  # file number for INPUT#
            if not isinstance(state.ax, ir.Lit):
                raise ValueError(f"non-literal file number at {addr:#x}")
            state.flush_pending()  # statement boundary
            state.pend_fnum = state.ax.value
            state.ax = None
            state.k += 1
            continue
        if handlers.graphics(state, op, addr, kind):
            continue
        if handlers.device_io(state, op, addr, kind):
            continue
        if handlers.segments(state, op, addr, kind):
            continue
        if handlers.devwait(state, op, addr, kind):
            continue
        if handlers.errors_trap(state, op, addr, kind):
            continue
        if handlers.datetime(state, op, addr, kind):
            continue

        if handlers.console(state, op, addr, kind):
            continue
        if handlers.graphics_box(state, op, addr, kind):
            continue

        if kind == "movm_imm":  # int var = constant, or VARPTR(v):
            val = ir.Lit(op[3])  # VARPTR compiles to the slot disp
            try:  # as an immediate but -- unlike a
                v = state.loc(op[3])  # true literal -- leaves NO pool
            except ValueError:  # copy (t1_varptr gate: 3-byte pool
                v = None  # diff), so pool membership decides
            if isinstance(v, ir.Var) and not _pool_has_word(
                exe, state.dsd, state.lay, op[3]
            ):
                val = ir.Call("VARPTR", (v,))
            state.put(ir.Assign(state.loc(op[2]), val), state.cur)
            state.cur = None
            state.k += 1
            continue
        if kind == "movm_ax":  # int var = ax expression
            state.put(ir.Assign(state.loc(op[2]), state.ax), state.cur)
            state.ax = None
            state.cur = None
            state.k += 1
            continue
        if handlers.os_system(state, op, addr, kind):
            continue
        if handlers.sound(state, op, addr, kind):
            continue
        if kind == "key_on" or kind == "key_off":  # KEY ON / KEY OFF
            state.put(ir.Key(kind == "key_on"), state.cur)
            state.cur = None
            state.k += 1
            continue
        if handlers.write_ops(state, op, addr, kind):
            continue
        if kind == "movsi":  # string operand by descriptor
            nxt = state.ops[state.k + 1][1:] if state.k + 1 < len(state.ops) else None
            d = cast(int, op[2])
            if nxt == ("rt", 0x9C):  # push (var desc or pooled literal)
                state.sstack.append(
                    state.loc(d) if d in state.lay["strs"] else state._pool_str(d)
                )
                state.k += 2
                continue
            if nxt == ("strassign",):  # pop-assign into a string var
                if state.pend_input is not None:  # ... as an INPUT's string read
                    prompt, flags = state.pend_input
                    if flags & ~0x4040 or flags & 0x4000:
                        raise ValueError(f"INPUT flags {flags:#06x} for string target")
                    state.put(
                        ir.Input(prompt, state.loc(d), comma=bool(flags & 0x0040)),
                        state.cur,
                    )
                    state.pend_input = None
                elif (
                    state.sstack and state.sstack[-1] is _FREAD
                ):  # INPUT# string target
                    state.sstack.pop()
                    state._fread_target(state.loc(d))
                elif (
                    state.sstack and state.sstack[-1] is _READDATA
                ):  # READ string target
                    state.sstack.pop()
                    state._readdata_target(state.loc(d))
                else:
                    state.put(ir.Assign(state.loc(d), state.sstack.pop()), state.cur)
                state.cur = None
                state.k += 2
                continue
            if nxt in (("far_spush",), ("far_strassign",)):
                # mov si, imm = constant ELEMENT OFFSET under ES=[blk]
                if state.pend_es is None:
                    raise ValueError(f"const far string op without ES at {addr:#x}")
                a = state.r_arrs[state.pend_es]
                if a["rank"] != 1 or not a.get("str"):
                    raise ValueError(
                        f"const-offset far string op mismatch at {addr:#x}"
                    )
                ref = ir.ArrayRef(a["name"], (ir.Lit(d // 4 + a["lo"][0]),))
                state.pend_es = None
                if nxt == ("far_spush",):
                    state.sstack.append(ref)
                else:
                    v = state.sstack.pop()
                    if v is _FREAD:  # INPUT# far string target
                        state._fread_target(ref)
                    else:
                        state.put(ir.Assign(ref, v), state.cur)
                    state.cur = None
                state.k += 2
                continue
            # Far array-element CALL arg: movsi d; movdx blk; movesdx; arg_push_arr
            if (
                state.k + 3 < len(state.ops)
                and state.ops[state.k + 1][1] == "movdx"
                and state.ops[state.k + 2][1] == "movesdx"
                and state.ops[state.k + 3][1] == "arg_push_arr"
            ):
                state.pend_args.append(
                    state.loc(d)
                )  # by-ref far array-element arg (resolved element)
                state.k += 4
                continue
            # LSET/RSET/MID$= : movsi d; movdx blk; movesdx; <op> (fixed-field string)
            if (
                state.k + 3 < len(state.ops)
                and state.ops[state.k + 1][1] == "movdx"
                and state.ops[state.k + 2][1] == "movesdx"
                and state.ops[state.k + 3][1] in ("lset", "rset", "midassign")
            ):
                op3 = state.ops[state.k + 3][1]
                target = state.loc(d)
                source = state.sstack.pop()
                if op3 == "lset":
                    state.put(ir.Lset(target, source), state.cur)
                elif op3 == "rset":
                    state.put(ir.Rset(target, source), state.cur)
                else:  # MID$(target$, start) = source$
                    if not isinstance(state.ax, ir.Lit):
                        raise ValueError(f"MID$= without start in ax at {addr:#x}")
                    state.put(ir.MidAssign(target, state.ax, source), state.cur)
                    state.ax = None
                state.cur = None
                state.k += 4
                continue
            raise ValueError(f"unhandled movsi continuation at {addr:#x}: {nxt}")
        if handlers.file_write(state, op, addr, kind):
            continue

        if handlers.runtime_call(state, op, addr, kind):
            continue
        if handlers.data_read(state, op, addr, kind):
            continue
        if handlers.fileio(state, op, addr, kind):
            continue
        if handlers.file_read(state, op, addr, kind):
            continue

        if handlers.data_read2(state, op, addr, kind):
            continue

        if kind == "moves_m":  # mov es,[block]: far access
            if op[2] not in state.r_arrs:
                raise ValueError(f"mov es from non-array cell {op[2]:#x} at {addr:#x}")
            state.pend_es = op[2]
            state.k += 1
            continue
        if handlers.far_fp(state, op, addr, kind):
            continue

        # --- Symbolic far-index machine: ax/bx/si carry plain Exprs
        # or index tokens ("jspan", blk, j) / ("inorm", blk, i) / ("idx", blk, idxs);
        # register moves shuttle them (the compiler's spill protocol around nested
        # element fetches); shl si x2 + mov es,[blk] + far op [si] consumes an "idx".
        if kind == "movsiax" or kind == "bchk_idx":
            # bchk_idx (Bounds `cd 93`) is the range-checked form of mov si,ax:
            # same si=ax transfer, so it lifts identically (F3.4).
            if (
                isinstance(state.ax, tuple) and state.ax[0] == "inorm"
            ):  # 1-D index complete
                if state.slot_info[state.ax[1]]["rank"] != 1:
                    raise ValueError(f"bare inorm for rank-2 array at {addr:#x}")
                state.si = ("idx", state.ax[1], (state.ax[2],))
            else:
                state.si = state.ax
            state.ax = None
            state.k += 1
            continue
        if handlers.filesystem(state, op, addr, kind):
            continue
        if handlers.file_random(state, op, addr, kind):
            continue

        if handlers.on_control(state, op, addr, kind):
            continue

        fp_dispatch(state, op, addr, kind)
    raise ValueError("op stream ended without the cleanup epilogue")
