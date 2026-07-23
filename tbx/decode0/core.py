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
    _JCC_RELOP_STR,
    _JCC_RELOP_TRUE,
    _PREC,
    _PUT_ACTIONS,
    _READDATA,
    _pp_commas,
)
from tbx.decode0.dialect import find_prologue
from tbx.decode0.scan import _grp, _orient, _rgrp, _scan
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
    _fold_body_ifgotos,
    _fold_if,
    _is_for_header,
    _loose_for_header,
    _jump_targets,
    _lift_midblock_troff,
    _lift_next,
    _lift_var_step_next,
    _resolve_targets,
)
from tbx.decode0.rename import _slot, _str_lit, canonical_rename

# Word count `local_init` reserves for a LOCAL DYNAMIC array's descriptor
# template -- a fixed size regardless of rank or element type (witnessed
# identical for rank-1 and rank-2 probes, q_localarr/q_locarr3); only 5 of
# the 30 words are ever written (handle, type/rank, esize, one bound pair),
# the rest is dead padding sized for the worst case the runtime supports.
_LOCAL_ARR_WORDS = 30


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
    direct_bool_gate: bool = False
    data_items: Any = None
    dos: Any = None
    ds: Any = None
    dsd: Any = None
    di: Any = None
    dx: Any = None
    exe: Any = None
    exit_folds: Any = None
    fn_args: Any = None
    fn_args_stack: Any = None
    fn_frame: dict[str, Any] | None = None
    fors: Any = None
    has_procs: Any = None
    have_fre: Any = None
    hook_seq: Any = None
    ifs: Any = None
    k: Any = None
    lay: Any = None
    local_dim_frame: dict[str, Any] | None = None
    main_start: Any = None
    metas: Any = None
    nfn: Any = None
    n_local_arrs: int = 0
    nsub: Any = None
    ops: Any = None
    option_base: Any = None
    pend_arg: Any = None
    pend_args: Any = None
    pend_bool: Any = None
    pend_bool_outer: Any = None
    pend_cmp: Any = None
    pend_cmp_str: bool = False  # pend_cmp came from strcmp: forward flags
    pend_dataread: Any = None
    pend_es: Any = None
    pend_field: Any = None
    pend_filein: Any = None
    pend_getstr: Any = None
    pend_fnum: Any = None
    pend_icmp: Any = None
    pend_input: Any = None
    pend_line_input: Any = None
    pend_mode_lit: Any = None
    pend_print: dict[str, Any] | None = None
    pend_shortstr: Any = None
    pend_swap: Any = None
    pend_swap_rev: Any = None
    pend_using: Any = None
    prev_dim_end: Any = None
    proc_frame: Any = None
    proc_names: Any = None
    proc_params: Any = None
    proc_int_offs: Any = None
    proc_str_offs: Any = None
    reg_logical_results: Any = None
    fp64_bridge: Any = None
    r_arrs: Any = None
    si: Any = None
    slot_info: Any = None
    sp_save_cell: Any = None
    sp_save_stack: Any = None
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
        """Double FP mem operand: variable/element via loc(), a pooled IEEE-754
        double literal (8 LE bytes) in the pool window, or a cached value from
        the transient fp64_bridge scratch cell (see its own comment).
        fpval at f64 width."""
        try:
            return self.loc(disp)
        except ValueError:
            if disp >= self.lay["pool_base"] - 4:
                return ir.DblLit(struct.unpack_from("<d", self.exe, self.dsd + disp)[0])
            if disp in self.fp64_bridge:
                return self.fp64_bridge[disp]
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
                # column-major: r = (i1-lo1) + (i2-lo2)*span1 + (i3-lo3)*span2
                spans = [1, *(a.get("spans") or [a["span"]])]
                subs = []
                for d in range(a["rank"]):
                    ext = a["hi"][d] - a["lo"][d] + 1
                    subs.append(ir.Lit(a["lo"][d] + (r // spans[d]) % ext))
                return ir.ArrayRef(a["name"], tuple(subs))
        raise ValueError(f"displacement {disp:#x} is neither scalar nor array element")

    def loc_local(self, bp_off):
        """A [bp+off] operand inside an open SUB or DEF FN body: a LOCAL
        statement's per-call stack slot (never a by-ref param, which is only
        ever reached indirectly through `les si,[bp+off]` -- witnessed
        t1_local1). Every slot in the zero-filled range is a 2-byte int for
        now (no fixture has witnessed a mixed-type LOCAL declaration yet)."""
        if self.proc_frame is not None:
            locs = self.proc_frame["locals"]
            if locs is None or bp_off not in locs:
                raise ValueError(f"[bp+{bp_off}] outside the open LOCAL frame")
            return ir.Var(locs[bp_off])
        if self.fn_frame is not None:
            locs = self.fn_frame["locals"]
            if locs is not None and bp_off in locs:
                return ir.Var(locs[bp_off])
            # Not a declared LOCAL: an integer-typed DEF FN param read via the
            # ax-register path (fp_bp handles the FP-typed equivalent) --
            # params aren't always the fixed 4-byte-stride slots a
            # float-only FN uses; an all-integer param list packs 2 bytes
            # apiece starting right after the result cell (wild resume.exe).
            self.fn_frame["param_offs"].add(bp_off)
            self.fn_frame["int_offs"].add(bp_off)
            return ir.Var(f"P{bp_off:02X}%")  # suffix must match the `params`
            # tuple's own spelling below, or rename.py sees two "different"
            # variables for the one param (byte-exact needs the declared
            # name and every body reference to agree)
        raise ValueError(f"[bp+{bp_off}] outside the open LOCAL frame")

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
        if self.pend_field is not None:
            pfd, self.pend_field = self.pend_field, None
            if not pfd["fields"]:
                raise ValueError("FIELD chain closed without any AS-entry")
            self.stmts.append(ir.Field(pfd["fnum"], tuple(pfd["fields"])))
            self.addrs.append(pfd["start"])
        if self.pend_print is not None:
            pp, self.pend_print = self.pend_print, None
            if pp.get("mode") == "write":  # WRITE / WRITE# has no trailing-';' form:
                self.stmts.append(ir.Write(tuple(pp["items"]), file=pp["file"]))
            elif pp.get("mode") == "lprint":  # trailing-';' LPRINT: closed by
                # the next completed statement, like console PRINT (witnessed
                # t1_lpusing -- an LPRINT USING follows with no B9 between)
                self.stmts.append(ir.Lprint(tuple(pp["items"]), newline=False))
            else:
                self.stmts.append(
                    ir.Print(
                        tuple(pp["items"]),
                        newline=False,
                        file=pp["file"],
                        commas=_pp_commas(pp),
                    )
                )
            self.addrs.append(pp["start"])
        if self.pend_using is not None:
            pu, self.pend_using = self.pend_using, None
            self.stmts.append(
                ir.PrintUsing(
                    pu["fmt"],
                    tuple(pu["values"]),
                    file=pu["file"],
                    newline=False,
                    lprint=pu.get("lprint", False),
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

    def _input_target(self, ref: object, is_str: bool) -> None:
        """Append a console-INPUT target; validate its per-position type bit
        (0x4000 >> k set = numeric, witnessed t1_inpmulti/t1_inpmixed) and
        emit the Input statement once every target has arrived."""
        pi = self.pend_input
        assert pi is not None
        k = len(pi["targets"])
        bit = 0x4000 >> k
        if bool(pi["flags"] & bit) == is_str:
            raise ValueError(
                f"INPUT target {k} type bit mismatch (flags {pi['flags']:#06x})"
            )
        pi["targets"].append(ref)
        if len(pi["targets"]) == pi["want"]:
            var = pi["targets"][0] if pi["want"] == 1 else tuple(pi["targets"])
            self.put(
                ir.Input(
                    pi["prompt"],
                    var,
                    comma=bool(pi["flags"] & 0x0040),
                    semi=bool(pi["flags"] & 0x0080),
                ),
                pi["start"],
            )
            self.pend_input = None

    def _lineinput_target(self, ref: object) -> None:
        """Resolve a LINE INPUT whose target is a computed string-array
        element (the `_LINEINPUTREAD` sibling of `_input_target`'s array
        case, wild cal87.exe): the index computation runs between the read
        and the element store, so the store names the target."""
        pi = self.pend_line_input
        assert pi is not None
        self.put(ir.LineInput(pi["prompt"], ref, semi=pi["semi"]), pi["start"])
        self.pend_line_input = None

    # decode a pooled string literal at descriptor `desc`; desc and ss_base are ints
    # wherever a string literal is present (else this is unreached)
    def _pool_str(self, desc: object) -> ir.StrLit:
        return _str_lit(self.exe, self.dsd, cast(int, desc), cast(int, self.ss_base))

    def vdisp(self, node):  # placeholder Var -> DS displacement
        return int(node.name[1:].rstrip("%&#"), 16)


def _region_refs(node) -> tuple[list[str], list[str]]:
    """(scalar placeholder names, array names) referenced in an IR fragment,
    each in first-appearance order. Dim counts as an array mention (it is one
    at compile time: a runtime DIM in main makes the array main's)."""
    vs: dict[str, None] = {}
    ars: dict[str, None] = {}

    def flat(v):
        if isinstance(v, tuple):
            for x in v:
                yield from flat(x)
        else:
            yield v

    def w(n):
        if isinstance(n, ir.Var):
            vs.setdefault(n.name)
        elif isinstance(n, ir.ArrayRef):
            ars.setdefault(n.name)
        elif isinstance(n, ir.Erase):
            ars.setdefault(n.name)
        elif isinstance(n, (ir.GetGfx, ir.PutGfx)):
            ars.setdefault(n.array)
        elif isinstance(n, ir.Dim):
            ars.setdefault(n.name)
            for nm, _ in n.also:
                ars.setdefault(nm)
        for f in getattr(n, "__dataclass_fields__", ()):
            for item in flat(getattr(n, f)):
                if hasattr(item, "__dataclass_fields__"):
                    w(item)

    for s in flat(node) if isinstance(node, (tuple, list)) else (node,):
        w(s)
    return list(vs), list(ars)


def _scope_procs(state: DecodeState) -> tuple[dict[int, ir.Shared], dict[str, int]]:
    """Slot-scope attribution for SUB bodies (witnessed t1_subsh/t1_subarr/
    t1_subad): TB gives every non-SHARED SUB variable/array its own local
    static slot, so a slot referenced both inside a SUB body and anywhere
    else can only be SHARED -- synthesize the declaration at body top.
    Returns ({top index -> Shared statement for that SUB}, {array name ->
    top index of the SUB it is local to} -- their synthesized DIM belongs
    inside that body). DEF FN bodies need no treatment: their unlisted
    variables are the main program's (existing DEF FN fixtures round-trip
    with no declarations)."""
    regions: list[tuple[int, list[str], list[str]]] = []
    for i, s in enumerate(state.stmts):
        if isinstance(s, ir.SubDef):
            vs, ars = _region_refs(s.body)
            # A SUB's formals are its own scope: two SUBs whose params share a
            # bp offset get the same P-name, which must not read as a cross-
            # region (SHARED) reference (q_fwd).
            vs = [v for v in vs if v not in s.params]
            regions.append((i, vs, ars))
    main_stmts = [s for s in state.stmts if not isinstance(s, ir.SubDef)]
    mvs, mars = _region_refs(tuple(main_stmts))
    shared_subs: dict[int, ir.Shared] = {}
    sub_local_arrays: dict[str, int] = {}
    for i, vs, ars in regions:
        other_v = set(mvs)
        other_a = set(mars)
        for j, ovs, oars in regions:
            if j != i:
                other_v |= set(ovs)
                other_a |= set(oars)
        names = [v for v in vs if v in other_v]
        names += [a + "()" for a in ars if a in other_a]
        sub_local_arrays.update({a: i for a in ars if a not in other_a})
        if names:
            shared_subs[i] = ir.Shared(tuple(names))
    return shared_subs, sub_local_arrays


def _resolve_calls(stmts, proc_names, proc_params, proc_int_offs, proc_str_offs):
    """A CALL to a SUB defined later in the file staged a ("addr", n)
    placeholder (see handlers.control.calls) since proc_names had no entry
    for it yet at that point in the scan; every SUB has been decoded by the
    time _finalize runs, so every entry is now resolvable (wild
    process.exe). A CallStmt can nest inside a SUB body (one SUB calling
    another) or a conditional arm, so this has to walk the same shapes
    _resolve_targets's own `fix()` recurses into, not just the top level --
    but unlike that walk, this one must preserve the `is` identity of every
    UNCHANGED statement: `_resolve_targets` (run right after this) keys
    `stmt_addr` off `id(stmt)` to place BodyLine jump targets inside SUB/IF
    bodies, so rebuilding a SubDef/IfBlock/etc that contains no pending call
    -- which is the common case, every time -- would silently orphan any
    jump target landing inside it (wild inv87.exe/invoice.exe: caught by a
    first version of this fix that rebuilt unconditionally).

    A forwarded by-ref arg (arg_push_fwd) to a callee ALSO defined later
    staged its own ("fwdpending", target, index, off) placeholder (see
    handlers.control.calls) since the callee's own param list wasn't known
    at that point either -- resolved here too, the same way (wild
    resume.exe)."""

    def fix_args(args):
        changed = False
        new_args = list(args)
        for i, a in enumerate(args):
            if isinstance(a, tuple) and a and a[0] == "fwdpending":
                _, target, _idx, off = a
                params = proc_params[target]
                sfx = params[_idx][-1] if params[_idx][-1] in "%$" else ""
                if sfx == "%":
                    proc_int_offs.add(off)
                elif sfx == "$":
                    proc_str_offs.add(off)
                new_args[i] = ir.Var(f"P{off:02X}{sfx}")
                changed = True
        return (tuple(new_args) if changed else args), changed

    def walk(body):
        new = [fix(s) for s in body]
        return body if all(a is b for a, b in zip(body, new)) else new

    def fix(s):
        if isinstance(s, ir.CallStmt):
            new_args, args_changed = fix_args(s.args)
            if isinstance(s.name, tuple):
                target = s.name[1]
                if target in proc_names:
                    return ir.CallStmt(proc_names[target], new_args)
                # Not a proc: once event trapping is active ANYWHERE in the
                # program, the compiler emits a far call/retf pair for a
                # PLAIN GOSUB too (RETURN -> retf under trapping, already
                # handled above; the far_call is its matching counterpart --
                # a near call/far ret would corrupt the stack). The target
                # is an ordinary statement, never a proc_enter, so it can
                # only resolve as a GOSUB line -- _resolve_targets's own
                # existing fix() picks up this ("addr", ...) sentinel the
                # same way it already does for the near "call" op's ir.Gosub
                # (t1_fargosub; wild resume.exe's 14-call "mid-flow far_call"
                # mystery).
                if new_args:
                    raise ValueError(
                        f"far_call to non-proc {target:#x} carries arguments"
                    )
                return ir.Gosub(("addr", target))
            if args_changed:
                return ir.CallStmt(s.name, new_args)
        if isinstance(s, ir.SubDef):
            new_body = walk(s.body)
            return s if new_body is s.body else ir.SubDef(s.name, s.params, tuple(new_body))
        if isinstance(s, ir.DefFn) and s.is_block:
            new_body = walk(s.body)
            return (
                s
                if new_body is s.body
                else ir.DefFn(s.name, s.params, tuple(new_body), True)
            )
        if isinstance(s, ir.IfInline):
            new_body = walk(s.body)
            return s if new_body is s.body else ir.IfInline(s.cond, tuple(new_body))
        if isinstance(s, ir.IfBlock):
            changed = False
            arms = []
            for c, b in s.arms:
                nb = walk(b)
                changed = changed or nb is not b
                arms.append((c, tuple(nb)))
            else_body = s.else_body
            if s.else_body is not None:
                neb = walk(s.else_body)
                if neb is not s.else_body:
                    changed = True
                    else_body = tuple(neb)
            return s if not changed else ir.IfBlock(tuple(arms), else_body)
        if isinstance(s, ir.SelectCase):
            changed = False
            arms = []
            for arm in s.arms:
                nb = walk(arm.body)
                changed = changed or nb is not arm.body
                arms.append(ir.CaseArm(arm.guards, tuple(nb)))
            case_else = s.case_else
            if s.case_else is not None:
                nce = walk(s.case_else)
                if nce is not s.case_else:
                    changed = True
                    case_else = tuple(nce)
            return s if not changed else ir.SelectCase(s.selector, tuple(arms), case_else)
        return s

    return walk(stmts)


def _finalize(state: DecodeState, addr) -> Program:
    """Program epilogue: static-DIM re-emit, control-flow folds, target
    resolution and canonical rename -> the finished Program."""
    state.stmts[:] = _resolve_calls(
        state.stmts,
        state.proc_names,
        state.proc_params,
        state.proc_int_offs,
        state.proc_str_offs,
    )
    # Error-trap line table, probed early -- before DATA/dims/COMMON/TRON
    # synthesis below mutates state.addrs -- so a codeless DATA statement
    # with no READ/RESTORE anywhere to trigger its recovery (wild
    # vhfprop.exe) can still be found from its ORPHAN table entry (see
    # `_line_table`'s docstring). state.stmt_addr is already fully
    # populated by this point (decode_user_code's dispatch loop, which
    # calls `_finalize` only once it's done). Gated the same as the final
    # lookup below: only probe when the ops show error-trap evidence, else
    # this linear EXE scan risks a spurious match in an unrelated program.
    data_orphan_lines: list[tuple[int, int]] = []
    orphan_offs: set[int] = set()  # every orphaned offset, independent of DATA/DIM
    do_lines: list[int] = []  # genuine (kept) synthesized DOs' own lines, in order
    table_active = False
    if any(
        o[1] in ("resume_pre", "on_error", "error_stmt")
        or (o[1] == "movax_m" and o[2] in (0x72, 0x74))
        for o in state.ops
    ):
        _early = _line_table(
            state.exe,
            state.start,
            state.addrs,
            addr,
            extra_offs={a + 4 - state.start for a in state.trace_tbl}
            | {a - state.start for a in state.stmt_addr.values() if a is not None},
        )
        if _early is not None:
            table_active = True
            data_orphan_lines = _early[1]
            orphan_offs = {o for o, _ in _early[1]}

    # A bare backward jmps with no head-test frame is ALWAYS canonicalized
    # to synthesized `DO ... LOOP` -- as a bare infinite `DO...LOOP` (core.py's
    # dispatch loop, "bare backward jmps = infinite DO") or, via
    # `_lift_do_tail`, as `DO...LOOP WHILE/UNTIL cond` -- since an explicit
    # DO and a plain `<n> ... GOTO <n>` / `<n> ... IF cond THEN GOTO <n>`
    # compile to byte-identical code and the decoder can't otherwise tell
    # which the source used. But DO, like DATA/DIM, gets its OWN codeless
    # line-table entry (probes q_do2/q_goto2/q_lt7: identical code either
    # way, but only the DO form leaves an orphan entry sharing the loop
    # body's offset) -- so once a table is active and shows NO orphan
    # there, the DO spelling would recompile with an extra entry the
    # original never had. wild vhfprop.exe: two such loops (one bare, one
    # WHILE-tail-test), neither with orphan evidence -- both are plain
    # GOTO/IfGoto loops. Un-synthesize them: drop the Do, retarget the
    # paired Loop as a Goto (bare) or IfGoto (WHILE, same polarity as the
    # tail test -- "continue if cond true" is exactly `IF cond THEN GOTO`;
    # UNTIL would need De Morgan negation of a possibly-compound LogOp,
    # unwitnessed, so it is left to raise below rather than guessed), all
    # matched by nesting order (DO/LOOP pairs cannot cross in a
    # well-formed program, so a stack pairs them correctly same as the
    # loop's own runtime `state.dos` nesting would).
    if table_active:
        # Every Do (bare or head-test) is pushed, so a head-test DO's own
        # closing (bare) Loop pops ITS Do and not some enclosing bare one --
        # only a BARE Do's pairing is recorded for possible conversion.
        do_stack: list[tuple[int, bool]] = []
        do_to_loop: dict[int, int] = {}
        for i, s in enumerate(state.stmts):
            if isinstance(s, ir.Do):
                do_stack.append((i, s.kind is None and s.cond is None))
            elif isinstance(s, ir.Loop) and do_stack:
                do_idx, is_bare = do_stack.pop()
                if is_bare:
                    do_to_loop[do_idx] = i
        off_to_line = dict(data_orphan_lines)
        drop: set[int] = set()
        claimed_offs: set[int] = set()  # genuine DO's own orphan entry
        do_idx_lines: dict[int, int] = {}  # do_idx -> its line, genuine DOs only
        for do_idx, loop_idx in do_to_loop.items():
            if state.addrs[do_idx] is not None:
                continue  # a real (non-synthesized) Do -- untouched
            host = state.addrs[do_idx + 1]
            if host is None:
                continue
            host_off = host - state.start
            if host_off in orphan_offs:
                claimed_offs.add(host_off)  # a genuine DO -- not DATA/DIM's to see
                do_idx_lines[do_idx] = off_to_line[host_off]
                continue
            loop_s = state.stmts[loop_idx]
            assert isinstance(loop_s, ir.Loop)
            if loop_s.kind == "UNTIL":
                # A LOOP UNTIL conversion needs De Morgan negation of a
                # possibly-compound LogOp. No fixture witnesses that source
                # shape, so fail loud rather than guess its canonical form.
                raise ValueError(
                    "codeless DO...LOOP UNTIL (no orphan evidence) has no "
                    "witnessed non-DO source construct to un-synthesize to"
                )
            if loop_s.kind == "WHILE":
                # `IF cond THEN <body-line>` compiles to exactly the same
                # materialize-and-back-jcc shape as `LOOP WHILE cond`, but
                # has no codeless DO line-table entry (t1_iftailerr; wild
                # vhfprop.exe). The condition polarity is already identical.
                state.stmts[loop_idx] = ir.IfGoto(loop_s.cond, ("addr", host))
                drop.add(do_idx)
                continue
            state.stmts[loop_idx] = ir.Goto(("addr", host))
            drop.add(do_idx)
        if drop:
            keep = [i for i in range(len(state.stmts)) if i not in drop]
            state.stmts[:] = [state.stmts[i] for i in keep]
            state.addrs[:] = [state.addrs[i] for i in keep]
        if claimed_offs:
            data_orphan_lines = [
                (o, ln) for o, ln in data_orphan_lines if o not in claimed_offs
            ]
        # Surviving genuine DOs' lines, in the order they'll be walked at
        # the final prog.lines construction below (ascending do_idx, minus
        # whatever `drop` removed ahead of them -- but drop only removes
        # OTHER do_idx entries, never shifts a kept one out of relative
        # order, so a plain sort by original do_idx matches final order).
        do_lines = [do_idx_lines[i] for i in sorted(do_idx_lines)]

    shared_subs, sub_local_arrays = _scope_procs(state)
    ob = state.option_base if state.option_base is not None else 0
    dims, local_dims, cur_ob = [], {}, 0  # BASIC default at program top
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
        if a["name"] in sub_local_arrays:
            # A SUB-local static array: its DIM belongs inside that body. Its
            # record precedes every main record (SUB bodies are textually
            # first, and records allocate in first-mention order), so
            # splitting it out cannot reorder allocations -- checked below.
            if want != cur_ob:
                raise ValueError(
                    "OPTION BASE change around a SUB-local array (no witness)"
                )
            if dims:
                raise ValueError(
                    "SUB-local array record after a main array record "
                    "(allocation order would flip; no witness)"
                )
            local_dims.setdefault(sub_local_arrays[a["name"]], []).append(
                ir.Dim(a["name"], bounds)
            )
            continue
        if want != cur_ob:
            dims.append(ir.OptionBase(want))
            cur_ob = want
        dims.append(ir.Dim(a["name"], bounds))
    if state.option_base == 1 and cur_ob != 1:  # runtime DIMs witness OB1
        dims.append(ir.OptionBase(1))  # (lo-store order)
    # Rebuild SUB bodies: SHARED declaration first, then local static DIMs,
    # then the decoded body (canonical order; verified byte-exact against the
    # t1_subsh/t1_subarr/t1_subad witnesses).
    for i, s in enumerate(state.stmts):
        if not isinstance(s, ir.SubDef):
            continue
        prefix = []
        if i in shared_subs:
            prefix.append(shared_subs[i])
        prefix.extend(local_dims.get(i, ()))
        if prefix:
            state.stmts[i] = ir.SubDef(s.name, s.params, tuple(prefix) + s.body)
    ins = 0  # static DIMs follow any proc definitions
    while ins < len(state.stmts) and isinstance(
        state.stmts[ins], (ir.SubDef, ir.DefFn)
    ):
        ins += 1
    dim_lines: list[int] | None = None
    if dims and data_orphan_lines and len(dims) == len(data_orphan_lines):
        # Static array DIM declarations are codeless too (recovered from
        # array bookkeeping records, not a scanned op) and normally
        # repositioned to this canonical spot -- but when the error-trap
        # line table shows exactly len(dims) orphan (codeless-statement)
        # entries in ONE cluster, that's independent evidence these DIMs
        # actually compiled INLINE at their original position (wild
        # vhfprop.exe: two static arrays, two orphan "500" entries; probe
        # q_lt6). Reposition + reline them there instead. A count
        # coincidence with an UNRELATED codeless construct (e.g. DATA) is
        # possible in theory but unwitnessed; the single-cluster check
        # below keeps this narrow.
        offs = {o for o, _ in data_orphan_lines}
        if len(offs) == 1:
            ins = state.addrs.index(state.start + next(iter(offs)))
            dim_lines = [ln for _, ln in data_orphan_lines]
            data_orphan_lines = []  # consumed -- DATA recovery below won't fire
    state.stmts[ins:ins] = dims
    state.addrs[ins:ins] = [None] * len(dims)
    # DATA is codeless: re-emit as a block at the very top. Recover the pool
    # when the program consumes it (a READ/RESTORE) so a string-literal pool
    # frame is never misread as DATA -- OR when the error-trap line table
    # itself shows a codeless-statement (ORPHAN) entry, independent evidence
    # a DATA statement compiled here even with no READ/RESTORE anywhere in
    # the program to trigger recovery otherwise (wild vhfprop.exe; probes
    # q_lt1/q_lt3 witnessed DATA's own orphan entry directly). Split into
    # DATA stmts at item 0 and at every RESTORE <line> target item index, so
    # the target maps to a real stmt.
    data_lines: list[int] | None = None  # one line per data_block entry, if known
    deftype_lines: list[int] = []  # one line per inserted DefType, in insertion order
    deftype_places: list[tuple[int, int]] = []
    data_places: list[tuple[int, int]] = []  # (borrowed offset, line) per DATA stmt
    if any(isinstance(s, (ir.Read, ir.Restore)) for s in state.stmts) or data_orphan_lines:
        items = state.data_items or _read_data_pool(state.exe)
        if not items and data_orphan_lines:
            # No DATA pool at all, yet orphan evidence remains: a DEFINT/
            # DEFSTR/DEFSNG/DEFDBL default-type declaration.
            # Confirmed via the oracle: DEFINT A-Z and DEFSTR S compile
            # byte-IDENTICAL programs once every variable is explicitly
            # suffixed (which tbx's own emitted source always is), so the
            # original keyword/letter-range is unrecoverable but also
            # inconsequential -- `ir.DefType` always renders as a fixed
            # canonical `DEFSNG A-Z`. Each orphan is independent (unlike
            # DATA's single-cluster item-split, a DEFxxx statement carries
            # no payload to split), so insert one placeholder per orphan at
            # its own borrowed offset, in table order.
            for off, ln in data_orphan_lines:
                j = state.addrs.index(state.start + off)
                state.stmts.insert(j, ir.DefType())
                state.addrs.insert(j, None)
                deftype_lines.append(ln)
            data_orphan_lines = []
        elif items:
            if data_orphan_lines:
                # A codeless DATA statement has no READ to anchor a split
                # point via RESTORE targets. `data_orphan_lines` (one entry
                # per original DATA statement, in source order) tells us
                # exactly how many statements to split into and each one's
                # line -- but not the ITEM boundary between them, since the
                # pool encodes items, not statement boundaries. Probe q_lt4
                # confirmed the boundary is irrelevant to compiled bytes
                # (`DATA 1: DATA 2,3,4` == `DATA 1,2: DATA 3,4` byte for
                # byte): only the STATEMENT COUNT and each one's LINE are
                # byte-significant. So give every statement but the last
                # exactly one item; the last absorbs the remainder.
                if any(
                    isinstance(s, ir.Restore) and isinstance(s.target, int)
                    for s in state.stmts
                ):
                    raise ValueError(
                        "codeless DATA statement alongside a RESTORE split "
                        "is unsupported (no witness)"
                    )
                # Every DATA statement needs at least one item. Any excess
                # orphan entries are another payload-free codeless construct;
                # canonicalize those to DefType. This also handles multiple
                # DATA clusters (wild metric.exe) because each recovered DATA
                # is inserted at its own borrowed offset below.
                n = min(len(items), len(data_orphan_lines))
                data_places = data_orphan_lines[:n]
                deftype_places = data_orphan_lines[n:]
                splits = set(range(n))
                data_lines = [ln for _, ln in data_places]
            else:
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
            if data_lines is not None:
                # DATA compiles in TEXTUAL/compile order, not pool order
                # (probe q_lt3: prepending unconditionally byte-diffs the
                # line table once the DATA statements' own lines are
                # byte-significant) -- insert immediately before whatever
                # statement shares each entry's borrowed offset, matching
                # where the compiler actually placed multiple clusters.
                for s, (off, _) in zip(data_block, data_places):
                    j = state.addrs.index(state.start + off)
                    state.stmts.insert(j, s)
                    state.addrs.insert(j, None)
            else:
                state.stmts[0:0] = data_block  # prepend: block pos = final index
                state.addrs[0:0] = [None] * len(data_block)
            # Insert payload-free codeless declarations after DATA placement;
            # when both borrow the same host offset this preserves table order.
            for off, ln in deftype_places:
                j = state.addrs.index(state.start + off)
                state.stmts.insert(j, ir.DefType())
                state.addrs.insert(j, None)
                deftype_lines.append(ln)
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
        state.stmts,
        state.addrs,
        targets=_jump_targets(state.stmts),
        stmt_addr=state.stmt_addr,
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
    # COMMON compiles to no ops -- only the DGROUP band stamps the layout
    # solver recovered (see layout._bands_layout). Synthesize the canonical
    # declaration as the first statement, named/typed via loc() like any
    # other slot (witnessed t1_common1).
    if state.lay.get("common_slots"):
        if fixed_lines is not None:
            raise ValueError("COMMON alongside TRON trace hooks is unsupported")
        state.stmts.insert(
            0, ir.Common(tuple(state.loc(d).name for d in state.lay["common_slots"]))
        )
        state.addrs.insert(0, None)
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
    prog = Program(
        canonical_rename(
            _resolve_targets(state.stmts, state.addrs, state.stmt_addr)
        )
    )
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
        _late = _line_table(
            state.exe,
            state.start,
            state.addrs,
            addr,
            extra_offs={a + 4 - state.start for a in state.trace_tbl}
            | {
                a - state.start
                for a in state.stmt_addr.values()
                if a is not None
            },  # folded-body statements have table entries too (wild vhfprop)
        )
        table = _late[0] if _late is not None else None
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
                pending_data_lines = iter(data_lines or ())
                pending_dim_lines = iter(dim_lines or ())
                pending_do_lines = iter(do_lines or ())
                pending_deftype_lines = iter(deftype_lines)
                lines = []
                for s, a in zip(prog, state.addrs):
                    queue = (
                        pending_data_lines
                        if isinstance(s, ir.Data)
                        else pending_dim_lines
                        if isinstance(s, (ir.Dim, ir.OptionBase))
                        else pending_do_lines
                        if isinstance(s, ir.Do)
                        else pending_deftype_lines
                        if isinstance(s, ir.DefType)
                        else None
                    )
                    if a is None and queue is not None:
                        ln = next(queue, None)
                        if ln is None:
                            raise TypeError  # falls through to the same
                        lines.append(ln)  # unsupported-shape ValueError below
                    else:
                        lines.append(table[a - state.start])
                prog.lines = lines
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
        if op[2] == 0x74:  # runtime cells, not user slots (FP-context
            state.stack.append(ir.Err())  # read, e.g. PRINT ERR --
        elif op[2] == 0x72:  # witnessed t1_suberr)
            state.stack.append(ir.Erl())
        elif op[2] in state.lay["scalars"]:
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
        elif op[2] < VAR_BASE and op[2] not in state.lay["scalars"]:
            # Transient promote-once/compare-many scratch cell (see
            # state.fp64_bridge's own comment) -- invisible in the source,
            # not a real variable.
            state.fp64_bridge[op[2]] = v
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
        if name in ("CHR$", "SPACE$", "MKI$", "INPUT$", "IOCTL$"):  # integer arg in ax
            args = (state.ax,)
            state.ax = None
        elif name == "INPUT$F":  # INPUT$(n, f): n in bx (shuttled), f in ax
            name = "INPUT$"
            f = state.ax
            state.ax = None
            n = state.bx
            state.bx = None
            args = (n, f)
        elif name == "STRING$S":  # STRING$(n, s$): n in ax, s$ on sstack
            name = "STRING$"
            n = state.ax
            state.ax = None
            args = (n, state.sstack.pop())
        elif name == "MID$2":  # MID$(s$, start): s$ on sstack, start in ax
            name = "MID$"
            n = state.ax
            state.ax = None
            args = (state.sstack.pop(), n)
        elif name in ("LEFT$", "RIGHT$"):  # string on sstack, count in ax
            n = state.ax
            state.ax = None
            args = (state.sstack.pop(), n)
        elif name == "MID$":  # s$ on sstack, start in bx, len in ax
            ln = state.ax
            state.ax = None
            st = state.bx
            state.bx = None
            args = (state.sstack.pop(), st, ln)
        elif name == "STRING$":  # n in bx (shuttled), ch in ax
            ch = state.ax
            state.ax = None
            n = state.bx
            state.bx = None
            args = (n, ch)
        elif name in (
            "INKEY$",
            "DATE$",
            "TIME$",
            "COMMAND$",
            "ERDEV$",
        ):  # zero-arg: bare keyword
            state.sstack.append(ir.Nullary(name))
            state.k += 1
            return
        elif name in ("UCASE$", "LCASE$", "ENVIRON$"):  # string arg via sstack
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
    elif kind == "instr3":  # INSTR start in ax, strings pushed haystack first
        needle = state.sstack.pop()
        haystack = state.sstack.pop()
        state.ax = ir.Call("INSTR", (state.ax, haystack, needle))
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
    elif kind == "fn_screen_color":  # SCREEN(row, col, color): cx, bx, ax
        state.ax = ir.Call("SCREEN", (state.cx, state.bx, state.ax))
        state.cx = state.bx = None
    elif kind == "fn_ax2":  # two-FP-arg ax intrinsic (POINT)
        y = state.stack.pop()
        x = state.stack.pop()
        state.ax = ir.Call(op[2], (x, y))
    elif kind == "popop":
        last = state.stack.pop()  # last-pushed is the textual LEFT
        first = state.stack.pop()  # (R-form FSUBRP: st1=st0-st1, and
        if (
            op[2] in "+*"
            and isinstance(last, ir.BinOp)
            and _PREC[last.op] > _PREC[op[2]]
            and isinstance(first, ir.BinOp)
            and _PREC[first.op] >= _PREC[op[2]]
        ):
            # Two BARE fold chains (I*100 + J*10): TB evaluates these
            # left-to-right, and they must re-emit without parens -- a
            # grouped operand compiles right-first, so adding them would
            # flip the push order (witnessed t1_dim3v; the grouped/call
            # shapes below are tier1_expr/expr2, t1_fresx). The first-pushed
            # chain may sit at EQUAL precedence (left-associativity keeps
            # the parse): `B * 2 - 1 + 180 * (A > 0)` must not respell
            # R-form, since the flipped textual order also flips int-pool
            # allocation order (witnessed t1_imulpool, 5-byte diff).
            state.stack.append(ir.BinOp(op[2], first, last))
        else:
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
        if state.stack:
            v = state.stack.pop()
        elif isinstance(state.ax, ir.Call):
            # An ax-arg/ax-returning intrinsic (LOC(n): `movax n; fn_ax_ax`)
            # feeding STRAIGHT into an FP-typed target with no explicit
            # fistp/movmem_ax/fild bridge at all -- the compiler promotes
            # ax to FP implicitly here rather than through the usual
            # int->FP round trip (wild be.exe/styllist.exe, probe q_loc1).
            v = state.ax
            state.ax = None
        else:
            raise ValueError(f"fstp with empty FP stack at {addr:#x}")
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
    elif kind == "icomp":  # m16 int var/pool-literal compare (mixed-type
        # IF/loop test against an FP-stack value; wild grdscn.exe et al.)
        mem = (
            state.loc(op[2]) if op[2] in state.lay["scalars"] else state.pool_lit(op[2])
        )
        state.pend_cmp = (mem, state.stack.pop())
    elif kind == "icomp_bp":  # LOCAL int compare (mixed-type IF/loop test
        # against an FP-stack value; the bp-relative sibling of icomp, wild
        # bmaster.exe/ifi.exe)
        state.pend_cmp = (state.loc_local(op[2]), state.stack.pop())
    elif kind == "icomp32":  # m32 long-int var/pool-literal compare: the
        # LONG (`&`) sibling of icomp (`IF X& > 5.5 THEN`; wild stat.exe)
        mem = (
            state.loc(op[2])
            if op[2] in state.lay["scalars"]
            else state.pool_lit32(op[2])
        )
        state.pend_cmp = (mem, state.stack.pop())
    elif kind == "fcomp64":  # m64 direct compare outside SELECT CASE (which
        # consumes its own): double var or pooled f64 (witnessed t1_dblarr)
        state.pend_cmp = (state.fpval64(op[2]), state.stack.pop())
    elif kind == "fcompp":  # both sides FP-computed: LHS pushed first, so
        rhs = state.stack.pop()  # flags (ST0 cmp ST1 = rhs cmp lhs) keep the
        state.pend_cmp = (state.stack.pop(), rhs)  # reversed FP orientation
    elif kind == "strcmp":  # string relational IF (outside SELECT CASE, which
        rhs = state.sstack.pop()  # consumes its own strcmp ops): forward flags
        state.pend_cmp = (state.sstack.pop(), rhs)
        state.pend_cmp_str = True
    elif kind == "orax" and state.pend_cmp is None and state.ax is not None:
        # `or ax,ax`: a just-computed value's truthiness tested directly,
        # with no preceding compare (wild metric.exe, an INKEY$ poll
        # loop). A BACKWARD jcc right after is a DO-loop's own tail edge
        # (same cc 75=WHILE/74=UNTIL mapping as _lift_do_tail), but with
        # no explicit compare to materialize first the LOOP condition is
        # the bare value itself, not an explicit "<> 0" -- byte-exact
        # check: `LOOP UNTIL LEN(K$) <> 0` recompiles DIFFERENT bytes
        # (the full movax-FFFF/jcc/incax materialize template) from
        # `LOOP UNTIL LEN(K$)`, and only the bare form matches wild
        # metric.exe (probe q_orax). A forward jcc (a plain `IF <value>
        # <> 0 THEN ...`) falls through to the generic pend_cmp path,
        # same as a real compare would feed it.
        nxt = state.ops[state.k + 1] if state.k + 1 < len(state.ops) else None
        if (
            nxt is not None
            and nxt[1] == "jcc"
            and nxt[2] in (0x74, 0x75)
            and nxt[3] < addr
            and nxt[3] in state.addrs
        ):
            loop_kind = "WHILE" if nxt[2] == 0x75 else "UNTIL"
            idx = state.addrs.index(nxt[3])
            state.stmts.insert(idx, ir.Do(None))
            state.addrs.insert(idx, None)
            state.put(ir.Loop(loop_kind, state.ax), state.cur)
            state.ax = None
            state.cur = None
            state.k += 2
            return
        state.pend_cmp = (state.ax, ir.Lit(0))
        state.ax = None
    elif kind == "fstsw":
        pass
    elif kind == "jcc":
        cc, t = op[2], op[3]
        nxt = state.ops[state.k + 1] if state.k + 1 < len(state.ops) else None
        prev = state.ops[state.k - 1] if state.k else None
        direct_bool = (
            state.pend_cmp is None
            and state.ax is not None
            and cc in (0x74, 0x75)
            and prev is not None
            and prev[1] in ("andaxbx", "oraxbx", "xoraxbx")
            and nxt is not None
            and nxt[1] in ("jmp", "jmpf")
            and t == nxt[0] + (5 if nxt[1] == "jmpf" else 3)
        )
        if cc == 0x75 and direct_bool and any(
            candidate[0] == nxt[2] - 2 and candidate[1] == "andaxbx"
            for candidate in state.ops[state.k + 2 :]
        ):
            # Short-circuit gate inside an ungrouped outer AND. The current
            # logical value stays in AX while the right operand is evaluated;
            # its movbxax/movrr spill sequence below preserves and combines it.
            # The far target is the address immediately after that final AND,
            # not a statement boundary (t1_nestedbool; wild styled/hfprop).
            state.direct_bool_gate = True
            state.k += 2
            return
        if cc == 0x74 and direct_bool and state.direct_bool_gate:
            # Direct-GOTO sibling of the inline-body form: JZ skips the far
            # jump when the completed logical value is false, so the far jump
            # itself is the source THEN target (t1_nestedgoto; wild styled).
            state.put(ir.IfGoto(state.ax, ("addr", nxt[2])), state.cur)
            state.ax = None
            state.direct_bool_gate = False
            state.cur = None
            state.k += 2
            return
        if (
            cc == 0x75
            and direct_bool
            # This witnessed inline body ends at a scanned op. A target in the middle
            # of a later materialized expression is a nested short-circuit
            # gate and needs its spill protocol preserved instead.
            and any(candidate[0] == nxt[2] for candidate in state.ops)
        ):
            # A parenthesized logical value can feed JNZ directly: the final
            # AX/BX fold already set ZF, so no separate `or ax,ax` or compare
            # materialization appears.  JNZ skips the following far jump when
            # the value is true; that far jump skips the inline body.  Keep the
            # BinOp/Group tree as a bare truthiness condition: spelling it as
            # `expr = 0` changes both its polarity and TB's lowering.
            state.flush_pending()
            state.ifs.append(
                {
                    "target": nxt[2],
                    # The direct flag use is itself evidence that the complete
                    # logical value was parenthesized in source; without this
                    # outer Group TB chooses its short-circuit IF template.
                    "cond": (
                        state.ax if state.direct_bool_gate else ir.Group(state.ax)
                    ),
                    "start": state.cur,
                    "idx": len(state.stmts),
                }
            )
            state.ax = None
            state.direct_bool_gate = False
            state.cur = None
            state.k += 2
            return
        relop_map = _JCC_RELOP_STR if state.pend_cmp_str else _JCC_RELOP
        if (
            state.pend_cmp
            and nxt
            and nxt[1] in ("jmp", "jmpf")
            and t == nxt[0] + (5 if nxt[1] == "jmpf" else 3)
        ):
            if cc not in relop_map:
                raise ValueError(f"unhandled IF jcc {cc:02x} at {addr:#x}")
            lhs, rhs = state.pend_cmp
            state.pend_cmp = None
            state.pend_cmp_str = False
            state.put(
                ir.IfGoto(ir.RelOp(relop_map[cc], lhs, rhs), ("addr", nxt[2])),
                state.cur,
            )
            state.cur = None
            state.k += 2
            return
        if state.pend_cmp_str:  # string direct conditional GOTO (taken = THEN):
            # forward strcmp flags, so the TRUE map is _JCC_RELOP_STR's inverse
            # (witnessed t1_strgodo `IF A$ = "X" THEN <line>` / wild schart.exe;
            # only "="/"<>" seen, remaining rows by the same forward derivation)
            true_str = {0x74: "=", 0x75: "<>", 0x73: ">=", 0x72: "<",
                        0x77: ">", 0x76: "<="}
            if cc not in true_str:
                raise ValueError(
                    f"string compare jcc {cc:02x} without skip-jmp at {addr:#x}"
                )
            lhs, rhs = state.pend_cmp
            state.pend_cmp = None
            state.pend_cmp_str = False
            state.put(
                ir.IfGoto(ir.RelOp(true_str[cc], lhs, rhs), ("addr", t)),
                state.cur,
            )
            state.cur = None
            state.k += 1
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
    elif kind in ("jmp", "jmpf"):
        t = op[2]
        frame = state.proc_frame if state.proc_frame is not None else state.fn_frame
        cmp_at_t = next((o for o in state.ops if o[0] == t), None)
        test_k = next((i for i, o in enumerate(state.ops) if o[0] == t), None)
        loose = (
            _loose_for_header(state.ops, test_k, state.stmts, state.vdisp)
            if test_k is not None
            else None
        )
        if loose is not None:
            lim, stp, vdisp = loose
            lim_s, stp_s, init_s = state.stmts[-3:]
            del state.stmts[-3:]
            a = state.addrs[-3]
            del state.addrs[-3:]
            state.put(ir.For(init_s.target, init_s.value, lim_s.value, stp_s.value), a)
            state.fors.append(
                {
                    "v": vdisp,
                    "lim": lim,
                    "stp": stp,
                    "test": t,
                    "body": state.ops[state.k + 1][0]
                    if state.k + 1 < len(state.ops)
                    else None,
                }
            )
        elif _is_for_header(state.stmts, state.vdisp):
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
            and cmp_at_t[1] in ("cmp_mi8", "cmp_mi16", "cmp_bpi8")
            and state.stmts
            and isinstance(state.stmts[-1], ir.Assign)
            and isinstance(state.stmts[-1].target, ir.Var)
            and cmp_at_t[2] == state.vdisp(state.stmts[-1].target)
        ):
            # Integer FOR header: `I% = init; jmp cmp_addr` where the op at the
            # target is `cmp word [I%], limit` (imm8 or, when the limit doesn't
            # fit a signed byte, imm16 -- q_forbig). Step defaults to 1 (inc_m);
            # a literal step other than +-1 rewrites this statement in place
            # once the matching addm_i8 is seen at the NEXT (q_forstep/
            # q_forstepneg). A LOCAL loop var uses the bp-relative forms
            # (mov_bp_imm init / cmp_bpi8 test / inc_bp step -- q_locidx);
            # vdisp on its L-name yields the bp offset, disjoint from static
            # disps (>= VAR_BASE). `init` need not be a literal -- `FOR I% =
            # N% TO 23` compiles this same shape via movm_ax instead of
            # movm_imm, the init value just being whatever expression was in
            # ax (wild tamstart.exe, probe q_forvarinit).
            init_s = state.stmts.pop()
            a = state.addrs.pop()
            state.put(
                ir.For(init_s.target, init_s.value, ir.Lit(cmp_at_t[3]), ir.Lit(1)),
                a,
            )
            if cmp_at_t[1] == "cmp_bpi8" and state.proc_frame is not None:
                # A literal-bound FOR over a LOCAL reserves its two unused
                # limit/step temp words in the LOCAL frame right after the
                # loop var (the frame analog of the static band's phantom
                # slots, q_forstep) -- they are not declared LOCALs (q_locidx)
                locs = state.proc_frame["locals"] or {}
                locs.pop(cmp_at_t[2] + 2, None)
                locs.pop(cmp_at_t[2] + 4, None)
            state.fors.append(
                {
                    "v": cmp_at_t[2],
                    "test": t,
                    "idx": len(state.stmts) - 1,
                    "step": 1,
                    "body": state.ops[state.k + 1][0]
                    if state.k + 1 < len(state.ops)
                    else None,
                }
            )
        elif (
            cmp_at_t is not None
            and cmp_at_t[1] in ("movax_m", "movax_bp")
            and state.stmts
            and isinstance(state.stmts[-1], ir.Assign)
            and isinstance(state.stmts[-1].target, ir.Var)
            and isinstance(state.stmts[-1].value, ir.Lit)
            and (nxt_t := next((o for o in state.ops if o[0] > t), None)) is not None
            and nxt_t[1]
            == {"movax_m": "cmpm_ax", "movax_bp": "cmpm_ax_bp"}[cmp_at_t[1]]
            and nxt_t[2] == state.vdisp(state.stmts[-1].target)
        ):
            # Integer FOR header, VARIABLE limit: the ops at the test are
            # `mov ax,[limit-temp]; cmp [I%],ax; jle body`, and the header
            # copies the TO expression into the temp just before the init
            # (`mov ax,[N%]; mov [temp],ax; mov [I%],1; jmp test`) -- fold
            # that copy back into the FOR so the temp slot never surfaces
            # as a variable (witnessed t1_fori). A LOCAL loop var uses the
            # bp-relative forms throughout (movax_bp/cmpm_ax_bp/mov_bp_imm --
            # vdisp and loc_local's L-names already disambiguate uniformly,
            # same as the literal-step/variable-step LOCAL FOR cases above;
            # wild bmaster.exe/ifi.exe, probe q_locforvarlim).
            init_s = state.stmts.pop()
            a = state.addrs.pop()
            limit = (
                state.loc_local(cmp_at_t[2])
                if cmp_at_t[1] == "movax_bp"
                else state.loc(cmp_at_t[2])
            )
            if (
                state.stmts
                and isinstance(state.stmts[-1], ir.Assign)
                and isinstance(state.stmts[-1].target, ir.Var)
                and state.vdisp(state.stmts[-1].target) == cmp_at_t[2]
            ):
                limit = state.stmts.pop().value
                a = state.addrs.pop()
            if cmp_at_t[1] == "movax_bp" and state.proc_frame is not None:
                # A variable-limit FOR over a LOCAL reserves the SAME
                # [step-temp, limit-temp] word pair as the literal-limit
                # case above, right after the loop var -- the step-temp
                # (v+2) is unused with a literal step and dropped
                # immediately, but the limit-temp (v+4, == cmp_at_t[2]) is
                # read again at every iteration's test (movax_bp reloads
                # it), so it can't be dropped yet; stash it and strip it
                # only once the SUB body is fully decoded (proc_ret),
                # mirroring the variable-STEP LOCAL case's step-temp
                # handling above.
                locs = state.proc_frame["locals"] or {}
                locs.pop(nxt_t[2] + 2, None)
                state.proc_frame.setdefault("hidden_locals", set()).add(
                    cmp_at_t[2]
                )
            state.put(
                ir.For(init_s.target, init_s.value, limit, ir.Lit(1)),
                a,
            )
            state.fors.append(
                {
                    "v": nxt_t[2],
                    "test": t,
                    "body": state.ops[state.k + 1][0]
                    if state.k + 1 < len(state.ops)
                    else None,
                }
            )
        elif (
            cmp_at_t is not None
            and cmp_at_t[1] == "movax_bp"
            and state.stmts
            and isinstance(state.stmts[-1], ir.Assign)
            and isinstance(state.stmts[-1].target, ir.Var)
            and isinstance(state.stmts[-1].value, ir.Lit)
            and (nxt_t := next((o for o in state.ops if o[0] > t), None)) is not None
            and nxt_t[1] == "arg_ref"
            and (nxt_t2 := next((o for o in state.ops if o[0] > nxt_t[0]), None))
            is not None
            and nxt_t2[1] == "far_cmpm_ax_si"
            and nxt_t[2] == state.vdisp(state.stmts[-1].target)
        ):
            # Integer FOR header, VARIABLE limit, BY-REF PARAM loop var: the
            # ES:[SI] mirror of the movax_m/movax_bp cases just above -- the
            # loop var is itself a by-ref INTEGER parameter (`arg_ref P; les
            # si,[bp+P]; cmp es:[si],ax`), used directly as the FOR
            # variable, so it never occupies a LOCAL slot itself -- only
            # the [step-temp, limit-temp] pair is reserved (limit-temp ==
            # step-temp + 2, same relationship as the pure-LOCAL case where
            # the loop var's own slot precedes them; wild bmaster.exe/
            # ifi.exe, probe q_byrefforvar).
            init_s = state.stmts.pop()
            a = state.addrs.pop()
            limit = state.loc_local(cmp_at_t[2])
            if (
                state.stmts
                and isinstance(state.stmts[-1], ir.Assign)
                and isinstance(state.stmts[-1].target, ir.Var)
                and state.vdisp(state.stmts[-1].target) == cmp_at_t[2]
            ):
                limit = state.stmts.pop().value
                a = state.addrs.pop()
            if state.proc_frame is not None:
                locs = state.proc_frame["locals"] or {}
                locs.pop(cmp_at_t[2] - 2, None)
                state.proc_frame.setdefault("hidden_locals", set()).add(
                    cmp_at_t[2]
                )
            state.put(
                ir.For(init_s.target, init_s.value, limit, ir.Lit(1)),
                a,
            )
            state.fors.append(
                {
                    "v": nxt_t[2],
                    "test": t,
                    "body": state.ops[state.k + 1][0]
                    if state.k + 1 < len(state.ops)
                    else None,
                }
            )
        elif (
            cmp_at_t is not None
            and cmp_at_t[1] == "orax_self"
            and state.ops[state.k - 1][1] in ("movax_m", "movax_bp")
            and len(state.stmts) >= 2
            and isinstance(state.stmts[-1], ir.Assign)
            and isinstance(state.stmts[-1].target, ir.Var)
            and isinstance(state.stmts[-1].value, ir.Lit)
            and isinstance(state.stmts[-2], ir.Assign)
            and isinstance(state.stmts[-2].target, ir.Var)
            and state.vdisp(state.stmts[-2].target) == state.ops[state.k - 1][2]
        ):
            # Integer FOR header, VARIABLE (computed) STEP: the step's sign
            # is unknown at compile time, so the header copies the STEP
            # expression into a temp cell right before the loop var's own
            # init (`mov ax,<step-expr>; mov [step-temp],ax; mov [I%],init;
            # mov ax,[step-temp]; jmp test`) -- fold that temp copy back
            # into the FOR's step field, mirroring the variable-limit case
            # just above (t1_fori) but for STEP instead of TO. The limit
            # isn't known yet here (it's inside the dual ascending/
            # descending compare at the orax_self test itself, decoded
            # below); a placeholder is patched in place once seen, the
            # mirror image of addm_i8's step patch-up for a literal-step
            # header (q_forvarstep/q_forvarstep2; wild menu.exe/stat.exe).
            # A LOCAL loop var uses the bp-relative forms throughout
            # (movax_bp/movm_ax_bp/mov_bp_imm/cmp_bpi8/addm_ax_bp -- vdisp
            # and loc_local's L-names already disambiguate uniformly, same
            # as the literal-step LOCAL FOR above; wild ziptest.exe,
            # probe q_localvarstep).
            init_s = state.stmts.pop()
            a = state.addrs.pop()
            step_s = state.stmts.pop()
            state.addrs.pop()
            if state.ops[state.k - 1][1] == "movax_bp" and state.proc_frame is not None:
                # A variable-STEP FOR over a LOCAL reserves a [limit-temp,
                # step-temp] pair as the LAST two words of the LOCAL span
                # (unlike the literal-step case above, where v+2/v+4 works
                # only because that fixture's loop var happens to be the
                # last declared local too) -- a literal limit (as here)
                # needs no runtime limit-temp, but both words are still
                # reserved and neither is a declared LOCAL (probe
                # q_localvarstep; wild ziptest.exe). Unlike the literal
                # case's temps, the step-temp IS read again at NEXT time
                # (movax_bp reloads it for the increment/sign-test), so it
                # can't be dropped from `locals` yet -- stash both disps
                # and strip them from the LOCAL statement's name list only
                # once the SUB body is fully decoded (proc_ret).
                step_disp = state.vdisp(step_s.target)
                state.proc_frame.setdefault("hidden_locals", set()).update(
                    (step_disp, step_disp + 2)
                )
            state.put(
                ir.For(init_s.target, init_s.value, ir.Lit(0), step_s.value),
                a,
            )
            state.fors.append(
                {
                    "v": state.vdisp(init_s.target),
                    "test": t,
                    "idx": len(state.stmts) - 1,
                    "var_step": True,
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
            else:  # bare (unconditional) EXIT SUB/DEF (witnessed t1_subgsb)
                state.put(exit_stmt, state.cur)
        else:
            state.put(ir.Goto(("addr", t)), state.cur)
        state.cur = None
    elif kind == "call":
        state.put(ir.Gosub(("addr", op[2])), state.cur)
        state.cur = None
    elif kind in ("ret", "retf"):  # retf = RETURN under event trapping
        state.put(ir.Return(), state.cur)
        state.cur = None
    elif kind == "return_to":
        state.put(ir.Return(("addr", op[2])), state.cur)
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
        elif op[2] < addr and op[2] in state.stmt_addr.values():
            # short GOTO to a NUMBERED line inside an already-folded block-IF
            # body (TB allows jumping into a block interior when the interior
            # line carries a number -- witnessed t1_blkgoto / wild inv87.exe);
            # resolves to ir.BodyLine at finalize
            state.put(ir.Goto(("addr", op[2])), state.cur)
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
        if a.get("dbl") and not a["name"].endswith("#"):
            a["name"] += "#"  # double arrays (type 06, esz 8) render with `#`
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
    state.pend_line_input = None  # (prompt, semi) awaiting a LINE INPUT read
    state.pend_fnum = None  # file number from the [0060] cell
    state.dim_frame = None  # open runtime-DIM bracket
    state.local_dim_frame = None  # open LOCAL-frame (heap-allocated) DIM bracket
    state.n_local_arrs = 0  # V# numbering tail for LOCAL DYNAMIC arrays
    state.prev_dim_end = None  # last allocate's addr: comma-chain test
    state.r_arrs = {}  # block disp -> runtime array info
    state.fp64_bridge = {}  # transient sub-VAR_BASE fstp64/fld64 scratch cache
    # (promote-once/compare-many idiom, e.g. `IF N%=1 THEN...ELSEIF N%=2
    # THEN...` promotes N% to DOUBLE once and rereads the cache for each
    # comparison -- the same "stage, then reread" shape as the fistp[0x2C]
    # IDX% bridge, just for a variable-position scratch cell instead of a
    # fixed one; wild resume.exe)
    state.option_base = None  # 0/1 from DIM lower-bound cells
    state.pend_es = None  # block disp loaded into ES (far access)
    state.pend_shortstr = None  # packed 1-char string awaiting `shortstr`
    state.pend_mode_lit = None  # OPEN's FOR-keyword mode, once materialized
    state.pend_swap = None  # first ArrayRef of an ES-aliased array-element SWAP
    state.pend_swap_rev = None  # first far ArrayRef of the reverse dynamic SWAP
    state.cx = None  # 2nd-level index stash / WAIT and-mask
    state.di = None  # 3rd-level spill stash for nested integer expressions
    state.si = None  # element-index register (raw index / idx token)
    state.reg_spills = {}  # scratch-cell saves used beyond the register spill chain
    # Expression identities produced by register-register logical folds.  The
    # identity follows a value through movbxax/movrr without making every
    # generic register assignment maintain a separate provenance flag.
    state.reg_logical_results = []
    state.bchk_subs = []  # Bounds: pending non-final subscripts (F3.5)
    state.pend_bool = None  # compound-IF first term awaiting its tail
    state.pend_bool_outer = None  # enclosing accumulator awaiting a deferred
    # inner mixed-precedence group's own close (A OR B AND C's "A OR")
    state.pend_print = None  # open PRINT item chain
    state.pend_using = None  # open PRINT USING value chain
    state.pend_filein = None  # open INPUT# target chain
    state.pend_getstr = None
    state.pend_dataread = None  # open READ target chain
    state.pend_field = None  # open FIELD AS-entry chain
    state.ifs = []  # open inline-IF bodies
    state.has_procs = any(
        o[1] in ("proc_enter", "fn_ret", "inline_sub", "opaque_helper")
        for o in state.ops
    )  # def region present
    state.proc_names = {}  # proc entry addr -> synthesized name (SUB1.., FNFN1..)
    state.proc_params = {}  # SUB entry addr -> params tuple (declaration order),
    # for typing forwarded by-ref args at nested CALL sites (q_fwd)
    # open SUB body {entry, idx} (idx into stmts) / open DEF FN body {.., result, max_off}
    state.proc_frame = None
    state.fn_frame = None
    state.fn_args = {}  # staged FN-call args: bp_off -> Expr (offset-ordered)
    state.fn_args_stack = []  # nested-call-as-argument scoping for fn_args,
    # the DEF FN sibling of sp_save_stack below: a DEF FN call used as its OWN
    # outer DEF FN call's argument must not drain/clear the outer's
    # partially-staged fn_args when the inner call's own fn_call runs
    # (t1_fnargcall; unlike SUB CALL, which is a statement and structurally
    # can't nest as an argument, DEF FN calls are expressions and can)
    state.main_start = None  # def-region end = entry-jmp target
    state.nsub = 0  # SUB counter (entry-offset order)
    state.nfn = 0  # DEF FN counter (entry-offset order)
    state.pend_arg = None  # by-ref param bp_off from arg_ref (les si,[bp+N])
    state.pend_args = []  # accumulated CALL args, drained by far_call
    state.sp_save_cell = None  # cell holding saved SP (literal-arg staging)
    state.sp_save_stack = []  # nested call-staging frames: a call used as its
    # OWN outer call's argument opens a new push_bp/mov_mem_sp/.../pop_bp
    # region before the outer's own movm_imm-glue cell is reached (wild
    # resume.exe) -- restored on the matching pop_bp
    state.proc_str_offs = (
        set()
    )  # bp_offs the open proc reads as strings (arg_ref;far_spush)
    state.proc_int_offs = set()  # bp_offs read as integers (far_cmpax_si)

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
    state.data_items = []
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
        # `d` already sits just past the last matched descriptor (or at pool_base
        # if none chained) -- anchor there rather than at pool_base itself, since
        # a large descriptor table (e.g. a static string array's per-element
        # descriptors chained into the same table, witnessed vhfprop.exe: 469
        # descriptors) can run for well over 0x400 bytes past pool_base, pushing
        # the char record's actual position outside the old fixed window.
        lo = (d + 15) & ~15
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
                # Unreferenced descriptors without FRE sites are DATA items.
                # The shared literal pool stores them in reverse source order;
                # code-referenced literals were removed by desc_disps above.
                for ln, ptr in reversed(unref):
                    text = exe[
                        state.dsd + state.ss_base + ptr : state.dsd
                        + state.ss_base
                        + ptr
                        + ln
                    ].decode("latin-1")
                    try:
                        float(text)
                        is_str = False
                    except ValueError:
                        is_str = True
                    state.data_items.append(ir.DataItem(text, is_str))
            else:
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
        if kind == "nop":
            state.k += 1
            continue
        if kind == "into":
            # Overflow-toggle check (0xCE, no operand): the compiler inserts
            # this after arithmetic that could overflow when the 'O' IDE
            # Options toggle is on. No source spelling (rides on
            # Program.toggles like Bounds/Stack test) and no IR effect --
            # skip in place, mid-expression, without disturbing state.cur
            # (witnessed q_ovf).
            state.k += 1
            continue
        if kind == "stack_chk":
            # Stack-test toggle ('S') room check before a CALL: cmp sp against
            # a callee-dependent threshold, raise error 7 if short. No source
            # spelling and no IR effect -- skip like "into" (witnessed q_stsub).
            state.k += 1
            continue
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
            body = _fold_body_ifgotos(body, fr["target"], state.stmt_addr)  # AFTER the addr
            # retention: the fold nests the tail statements, and their (and the
            # consumed IfGoto's) addrs must stay visible to the line table
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
        if (
            state.has_procs
            and kind == "jmp"
            and state.main_start is None
            and state.fn_frame is None
            and state.proc_frame is None
            and len(state.stmts) == 1
            and isinstance(state.stmts[0], ir.OnError)
        ):
            # `ON ERROR GOTO` as the program's very first statement, ahead
            # of the entry skip-jmp (wild wb.exe): the k==0 case above
            # assumes the skip-jmp IS op 0, but a real leading statement can
            # precede it. Recognized narrowly (exactly one prior statement,
            # and it's ON ERROR) rather than generically allowing any
            # leading statement, since a real early GOTO must not be
            # swallowed as glue.
            state.main_start = op[2]
            state.k += 1  # glue, not a GOTO
            continue
        if (
            state.has_procs
            and kind == "jmp"
            and addr == state.main_start
            and state.k + 1 < len(state.ops)
            and state.ops[state.k + 1][1]
            in ("proc_enter", "inline_sub", "opaque_helper")
        ):  # chained skip-jmp: consecutive SUB defs are each bracketed by
            # their own jmp, so the entry jmp lands on the next def's jmp;
            # extend the def region to its target (witnessed q_fwd; the
            # inline_sub sibling is probe q_shriek's `SUB ... INLINE`)
            state.main_start = op[2]
            state.k += 1  # glue, not a GOTO
            continue
        if (
            state.has_procs
            and kind == "jmp"
            and state.fn_frame is None
            and state.proc_frame is None
            and state.k > 0
        ):
            j = state.k - 1
            while j >= 0 and state.ops[j][1] == "trap_hook":
                j -= 1  # event-trapping stamps sit between the closer and the jmp
            if j < 0 or state.ops[j][1] in ("proc_ret", "fn_ret"):
                # Not every file brackets its WHOLE def region with one leading
                # skip-jmp (the k==0 case above): some interleave definitions
                # with main code, each bracketed by its own trailing jmp right
                # after the previous def's closer -- so main_start never gets
                # set by the k==0 case at all. A jmp appearing exactly where a
                # definition just closed is unambiguously more of that same
                # glue (witnessed resume.exe: `proc_ret,8 / trap_hook / jmp`
                # lands right before an un-proc_enter'd DEF FN body -- without
                # this, the DEF FN's own auto-open below never fires because
                # it's gated on `addr < main_start`, which stays None forever).
                state.main_start = op[2]
                state.k += 1  # glue, not a GOTO
                continue
        if kind == "inline_sub":  # SUB name INLINE: the compiler copies
            # $INLINE's byte list verbatim with NO proc_enter/proc_ret
            # framing at all (see _try_inline_rescue in scan.py) -- no
            # params, no body statements to accumulate, so unlike every
            # other procedure this is complete in one op (probe q_shriek).
            state.nsub += 1
            name = f"SUB{state.nsub}"
            state.proc_names[addr] = name
            state.proc_params[addr] = ()
            state.stmts.append(ir.SubDef(name, (), (ir.Inline(op[2]),)))
            state.addrs.append(None)  # a SUB definition is never a jump target
            state.cur = None
            state.k += 1
            continue
        if kind == "opaque_helper":
            # Coverage-only recovery for a fully fingerprinted framed helper.
            # Its declaration-order parameter offsets are known from the BP
            # frame, but its source semantics and parameter types are not.
            state.nsub += 1
            name = f"SUB{state.nsub}"
            params = tuple(f"P{off:02X}" for off in op[3])
            state.proc_names[addr] = name
            state.proc_params[addr] = params
            state.stmts.append(ir.SubDef(name, params, (ir.OpaqueHelper(op[2]),)))
            state.addrs.append(None)
            state.cur = None
            state.k += 1
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
                "param_offs": set(),  # bp offsets touched as a param read/
                # fold/result -- the actual set IS the param list (not every
                # param uses the same byte stride: an all-FP or all-string
                # param list packs 4 bytes apiece, an all-integer one packs 2
                # -- wild resume.exe, probe_d)
                "exit": next(o[0] for o in state.ops[state.k :] if o[1] == "fn_ret"),
                "block": False,
                "str": False,  # string-valued FN (result stored via INT A2)
                "str_offs": set(),  # bp offsets of string params (INT 9E)
                "int_offs": set(),  # bp offsets of INTEGER params (ax-path
                # reads, e.g. movax_bp/imul_bp/fild_bp -- the source needs
                # the explicit `%` suffix to recompile byte-exact, mirroring
                # SUB's proc_int_offs)
                "locals": None,  # a DEF FN body's own LOCAL declaration, if any
            }
            state.cur = None  # fall through to lift this op into the body
        if kind == "proc_enter":
            state.flush_pending()
            state.proc_frame = {
                "entry": addr,
                "idx": len(state.stmts),
                "exit": next(o[0] for o in state.ops[state.k :] if o[1] == "proc_ret"),
                "locals": None,
            }
            state.proc_str_offs = set()
            state.proc_int_offs = set()
            state.cur = None
            state.k += 1
            continue
        if kind == "local_init":  # LOCAL statement's zero-fill prologue
            frame = (
                state.proc_frame if state.proc_frame is not None else state.fn_frame
            )
            if frame is None or len(state.stmts) != frame["idx"]:
                raise ValueError(
                    f"LOCAL zero-fill outside a fresh SUB/DEF FN body at {addr:#x}"
                )
            cnt, disp = op[2], op[3]
            frame["locals"] = {
                disp + 2 * i: f"L{disp + 2 * i:02X}%" for i in range(cnt)
            }
            if state.proc_frame is not None:
                state.proc_frame["frame_words"] = cnt  # retf pop math needs the
                # full zero-filled span even after FOR temp words are dropped
                # from the dict (q_locidx) -- a SUB-only concern: DEF FN's
                # fn_ret closing has no analogous pop-count computation
            state.cur = None
            state.k += 1
            continue
        if (
            kind == "mov_bp_imm"
            and state.local_dim_frame is None
            and state.k + 3 < len(state.ops)
            and state.ops[state.k + 1][1] == "mov_bp_imm"
            and state.ops[state.k + 2][1] == "far_ref_bp"
            and state.ops[state.k + 3][1] == "dim_begin"
            and state.ops[state.k + 2][2] == op[2] - 2
            and state.ops[state.k + 1][2] == op[2] + 4
        ):  # LOCAL DYNAMIC array (`LOCAL A()` + runtime `DIM A(n)`): opens
            # with a duplicate type/rank + element-size write (re-written
            # again once dim_begin/dim_end brackets the bound cells below),
            # then the LOCAL-frame sibling of the ordinary movsi/movdx/
            # movesdx-fronted DGROUP $DYNAMIC bracket, keyed by frame disp
            # instead of a DGROUP block (probe q_localarr)
            if state.proc_frame is None:  # DEF FN LOCAL arrays unwitnessed
                raise ValueError(f"LOCAL DIM bracket outside a SUB body at {addr:#x}")
            disp = op[2] - 2
            state.local_dim_frame = {
                "disp": disp,
                "cells": {2: ir.Lit(op[3]), 6: ir.Lit(state.ops[state.k + 1][3])},
                "start": state.cur,
            }
            state.cur = None
            state.k += 4  # type write, esize write, far_ref_bp, dim_begin
            continue
        if (
            kind == "mov_bp_imm"
            and state.local_dim_frame is not None
            and state.local_dim_frame["disp"]
            <= op[2]
            < state.local_dim_frame["disp"] + ARR_BLOCK
        ):  # LOCAL DYNAMIC array descriptor field write (type/size/bounds)
            state.local_dim_frame["cells"][op[2] - state.local_dim_frame["disp"]] = (
                ir.Lit(op[3])
            )
            state.k += 1
            continue
        if kind == "far_ref_bp" and state.k + 1 < len(state.ops) and (
            state.ops[state.k + 1][1] == "dim_end"
        ):  # dim_end: finalize the LOCAL DYNAMIC array descriptor opened above
            disp = op[2]
            if state.local_dim_frame is None or state.local_dim_frame["disp"] != disp:
                raise ValueError(f"unbalanced LOCAL DIM bracket at {addr:#x}")
            cells = state.local_dim_frame["cells"]
            if 2 not in cells or 6 not in cells:
                raise ValueError(
                    f"LOCAL DIM descriptor missing type/size fields at {addr:#x}"
                )
            type_rank, esize = cells.pop(2), cells.pop(6)
            if not isinstance(type_rank, ir.Lit) or not isinstance(esize, ir.Lit):
                raise ValueError(
                    f"non-literal LOCAL DIM descriptor fields at {addr:#x}"
                )
            tb, rank = type_rank.value & 0xFF, type_rank.value >> 8
            if rank != 1:  # rank > 1 needs the span-based index machine to
                raise ValueError(  # learn this shape too -- unwitnessed
                    f"unsupported LOCAL DIM rank {rank} at {addr:#x}"
                )
            if tb not in (0x00, 0x04):  # integer / single -- only two
                raise ValueError(  # element types witnessed so far
                    f"unsupported LOCAL DIM element type {tb:#x} at {addr:#x}"
                )
            expect_esz = 2 if tb == 0x00 else 4
            if esize.value != expect_esz:
                raise ValueError(f"LOCAL DIM element size mismatch at {addr:#x}")
            order = list(cells)
            lo, hi = cells.get(8), cells.get(0xA)
            if lo is None or hi is None or len(cells) != 2:
                raise ValueError(
                    f"LOCAL DIM bound cells incomplete at {addr:#x}: {cells}"
                )
            if not isinstance(lo, ir.Lit) or lo.value not in (0, 1):
                raise ValueError(
                    f"unexpected LOCAL DIM lower bound at {addr:#x}: {lo}"
                )
            # Explicit `lo:hi` ranges store lo BEFORE hi (textual order); the
            # default lo under OPTION BASE is patched in AFTER hi (same
            # convention as the ordinary DGROUP $DYNAMIC bracket).
            expl = order.index(8) < order.index(0xA)
            if not expl:
                if state.option_base not in (None, lo.value):
                    raise ValueError("inconsistent OPTION BASE across DIMs")
                state.option_base = lo.value
            suffix = "%" if tb == 0x00 else ""
            name = (
                f"V{state.lay['n_static'] + len(state.lay['rt_blocks']) + state.n_local_arrs}"
                f"{suffix}"
            )
            state.n_local_arrs += 1
            rec = {
                "name": name,
                "rank": 1,
                "str": False,
                "esz": expect_esz,
                "lo": [lo.value],
            }
            state.r_arrs[disp] = rec
            state.slot_info[disp] = rec
            bounds = (lo.value, hi) if expl else hi
            state.put(
                ir.Dim(name, (bounds,), dynamic=False),
                state.local_dim_frame["start"],
            )
            # Fold the whole reserved template out of the SUB's plain scalar
            # LOCAL slots (private array bookkeeping, not user variables --
            # only 5 of its 30 reserved words are ever written, the rest is
            # dead padding in a fixed-size template used regardless of rank/
            # type, witnessed identical for both rank-1 and rank-2 probes)
            # and register the array's own name in the handle's place, so
            # `LOCAL <name>()` renders where `LOCAL A()` appeared in source.
            assert state.proc_frame is not None
            if not state.proc_frame["locals"]:
                raise ValueError(f"LOCAL DIM without a LOCAL declaration at {addr:#x}")
            if state.proc_frame.get("frame_words") != _LOCAL_ARR_WORDS:
                raise ValueError(  # a LOCAL array mixed with other LOCALs in
                    f"unsupported LOCAL frame shape at {addr:#x}"  # the same
                )  # SUB is unwitnessed -- only a sole array is calibrated
            state.proc_frame.setdefault("hidden_locals", set()).update(
                disp + 2 * i for i in range(1, _LOCAL_ARR_WORDS)
            )
            state.proc_frame["locals"][disp] = f"{name}()"
            state.local_dim_frame = None
            state.cur = None
            state.k += 2
            continue
        if kind == "proc_ret":
            assert state.proc_frame is not None  # proc_ret only closes an open SUB body
            state.flush_pending()
            _apply_exit_folds(
                state.stmts, state.addrs, state.exit_folds
            )  # EXIT SUB fold (Task 3.5), body-local
            state.exit_folds.clear()
            body = tuple(state.stmts[state.proc_frame["idx"] :])
            for st, ad in zip(body, state.addrs[state.proc_frame["idx"] :]):
                if ad is not None:  # keep body addrs: GOSUB targets a body
                    state.stmt_addr[id(st)] = ad  # line (t1_subgsb)
            del (
                state.stmts[state.proc_frame["idx"] :],
                state.addrs[state.proc_frame["idx"] :],
            )
            locs = state.proc_frame["locals"]
            for d in state.proc_frame.get("hidden_locals") or ():
                if locs is not None:
                    locs.pop(d, None)  # var-STEP FOR temps (see above): never
            if locs:  # declared LOCALs, just deferred out of the dict
                # until every reference to them was resolved. The
                # zero-fill always runs right after proc_enter, regardless
                # of where LOCAL appears in source, so it's always the
                # body's first physical line (t1_local1)
                body = (ir.Local(tuple(locs.values())),) + body
            state.nsub += 1
            name = f"SUB{state.nsub}"
            state.proc_names[state.proc_frame["entry"]] = name
            # retf pop bytes = 4 x nargs, PLUS the LOCAL frame's own span: the
            # locals' stack space is caller-allocated too, so retf pops it
            # right along with the params (witnessed t1_local2)
            nparams = (
                op[2] - 2 * state.proc_frame.get("frame_words", len(locs or ()))
            ) // 4
            params = tuple(
                f"P{off:02X}$"
                if off in state.proc_str_offs
                else (f"P{off:02X}%" if off in state.proc_int_offs else f"P{off:02X}")
                for off in (6 + 4 * (nparams - 1 - i) for i in range(nparams))
            )
            state.proc_params[state.proc_frame["entry"]] = params
            state.stmts.append(ir.SubDef(name, params, body))
            state.addrs.append(None)  # a SUB definition is never a jump target
            state.proc_frame = None
            state.cur = None
            state.k += 1
            continue
        if handlers.calls(state, op, addr, kind):
            continue
        # --- DEF FN body & value-returning FN call ---
        if kind == "mov_bp_imm":  # [bp+n]=0 result-slot init in a DEF FN body:
            # numeric/block FNs zero [bp+0] AND [bp+2]; a single-line STRING
            # FN zeroes only [bp+2] (the descriptor's pointer word) -- so
            # only the [bp+0] init marks the multi-line form (t1_fnstr).
            frame = state.proc_frame if state.proc_frame is not None else state.fn_frame
            if (
                frame is not None and (frame["locals"] or {}).get(op[2]) is not None
            ):  # LOCAL int var = constant, e.g. a FOR init (q_locidx) -- same
                # shape whether the LOCAL lives in a SUB or a DEF FN body
                # (wild resume.exe: `LOCAL B% ... B% = 5` inside a DEF FN);
                # checked BEFORE the DEF-FN reserved-cell branch below since a
                # LOCAL can reuse a low bp offset the result slot doesn't use
                # (e.g. a zero-param FN's first LOCAL sits at bp+2).
                if state.cur is None:
                    state.cur = addr
                state.put(
                    ir.Assign(state.loc_local(op[2]), ir.Lit(op[3])), state.cur
                )
                state.cur = None
                state.k += 1
                continue
            if state.fn_frame is not None:
                if op[2] == 0:
                    state.fn_frame["block"] = True
                elif op[2] != 2:
                    raise ValueError(f"[bp+{op[2]}] init in DEF FN body at {addr:#x}")
            elif op[3] != 0:  # caller: literal-int FN-call arg staging (wild
                state.fn_args[op[2]] = ir.Lit(op[3])  # resume.exe, probe_d) --
                # a zero literal is indistinguishable from the zero-init of a
                # staged string-arg descriptor pointer (t1_fnstr) and stays
                # unsupported until a fixture disambiguates the two.
            state.k += 1
            continue
        if kind == "fn_ret":  # close the open DEF FN body
            assert state.fn_frame is not None  # fn_ret only closes an open DEF FN body
            # The touched bp offsets ARE the param list, in ascending order:
            # an all-FP or all-string param list packs 4 bytes/param (P04,
            # P08, ...), an all-integer one packs 2 (P04, P06, ... -- wild
            # resume.exe, probe_d) -- no fixed stride can be assumed.
            params = tuple(
                f"P{off:02X}$"
                if off in state.fn_frame["str_offs"]
                else (
                    f"P{off:02X}%" if off in state.fn_frame["int_offs"] else f"P{off:02X}"
                )
                for off in sorted(state.fn_frame["param_offs"])
            )
            state.nfn += 1
            name = f"FNFN{state.nfn}" + ("$" if state.fn_frame["str"] else "")
            state.proc_names[state.fn_frame["entry"]] = name
            if state.fn_frame["block"]:  # multi-line DEF FN ... END DEF
                _apply_exit_folds(
                    state.stmts, state.addrs, state.exit_folds
                )  # EXIT DEF fold (body-local)
                state.exit_folds.clear()
                body = tuple(state.stmts[state.fn_frame["idx"] :])
                for st, ad in zip(body, state.addrs[state.fn_frame["idx"] :]):
                    if ad is not None:  # keep body addrs (as in the SUB fold)
                        state.stmt_addr[id(st)] = ad
                del (
                    state.stmts[state.fn_frame["idx"] :],
                    state.addrs[state.fn_frame["idx"] :],
                )
                locs = state.fn_frame["locals"]
                if locs:  # declared LOCALs (wild resume.exe), mirroring
                    body = (ir.Local(tuple(locs.values())),) + body  # proc_ret
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
        if state.pend_arg is not None and kind == "far_strassign":
            # Far string assignment through a by-reference SUB parameter:
            # STRING$ (or another string expression) leaves the value on the
            # string stack, and LES SI,[BP+off] + far_strassign stores it into
            # the caller's descriptor (wild morcalc.exe).
            off = state.pend_arg
            state.proc_str_offs.add(off)
            state.put(ir.Assign(ir.Var(f"P{off:02X}$"), state.sstack.pop()), state.cur)
            state.pend_arg = None
            state.cur = None
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
            elif base == "fild_si":  # by-ref int param onto the FP stack,
                argvar = ir.Var(f"P{state.pend_arg:02X}%")  # e.g. for PRINT
                state.proc_int_offs.add(state.pend_arg)  # (t1_byref1)
                state.stack.append(argvar)
            elif base == "cmpax_si":  # cmp ax, es:[si]: relational value vs a
                argvar = ir.Var(f"P{state.pend_arg:02X}%")  # by-ref INT param
                state.proc_int_offs.add(state.pend_arg)  # (t1_cmpfar)
                state.pend_icmp = (argvar, state.ax)
                state.ax = None
            elif base == "addax_si":  # add ax, es:[si]: arithmetic fold of a
                argvar = ir.Var(f"P{state.pend_arg:02X}%")  # by-ref INT param
                state.proc_int_offs.add(state.pend_arg)  # (t1_local2)
                state.ax = ir.BinOp("+", argvar, _rgrp("+", state.ax))
            elif base == "subax_si":  # sub ax, es:[si]: subtractive fold of a
                argvar = ir.Var(f"P{state.pend_arg:02X}%")  # by-ref INT param,
                state.proc_int_offs.add(state.pend_arg)  # mem on the right
                state.ax = ir.BinOp("-", state.ax, _rgrp("-", argvar))  # like subax_m
            elif base == "andax_si":  # and ax, es:[si]: bitwise fold of a
                argvar = ir.Var(f"P{state.pend_arg:02X}%")  # by-ref INT param
                state.proc_int_offs.add(state.pend_arg)  # (t1_byref1)
                state.ax = ir.BinOp("AND", argvar, _rgrp("AND", state.ax))
            elif base == "orax_si":  # or ax, es:[si]: bitwise OR fold of a
                argvar = ir.Var(f"P{state.pend_arg:02X}%")  # by-ref INT param
                state.proc_int_offs.add(state.pend_arg)  # (wild pwinst.exe)
                state.ax = ir.BinOp("OR", argvar, _rgrp("OR", state.ax))
            elif base == "imulax_si":  # imul word es:[si]: multiplicative
                argvar = ir.Var(f"P{state.pend_arg:02X}%")  # fold of a by-ref
                state.proc_int_offs.add(state.pend_arg)  # INT param (q_byref_imul)
                state.ax = ir.BinOp("*", argvar, _rgrp("*", state.ax))
            elif base == "movax_si":  # mov ax, es:[si]: plain read of a
                argvar = ir.Var(f"P{state.pend_arg:02X}%")  # by-ref INT param,
                state.proc_int_offs.add(state.pend_arg)  # e.g. an expression's
                state.ax = argvar  # first term (t1_byref1)
            elif base == "movm_ax_si":  # mov es:[si], ax: write ax into a
                argvar = ir.Var(f"P{state.pend_arg:02X}%")  # by-ref INT param
                state.proc_int_offs.add(state.pend_arg)  # (t1_byref1)
                state.put(ir.Assign(argvar, state.ax), state.cur)
                state.ax = None
                state.cur = None
            elif base == "addm_ax_si":  # add es:[si], ax: compound-store add
                argvar = ir.Var(f"P{state.pend_arg:02X}%")  # into a by-ref INT
                state.proc_int_offs.add(state.pend_arg)  # param (q_fwd)
                state.put(
                    ir.Assign(argvar, ir.BinOp("+", argvar, _rgrp("+", state.ax))),
                    state.cur,
                )
                state.ax = None
                state.cur = None
            elif base == "subm_ax_si":  # sub es:[si], ax: compound-store
                argvar = ir.Var(f"P{state.pend_arg:02X}%")  # subtract into a
                state.proc_int_offs.add(state.pend_arg)  # by-ref INT param
                state.put(
                    ir.Assign(argvar, ir.BinOp("-", argvar, _rgrp("-", state.ax))),
                    state.cur,
                )
                state.ax = None
                state.cur = None
            elif base == "movm_imm_si":  # mov word es:[si], imm16: write a
                argvar = ir.Var(f"P{state.pend_arg:02X}%")  # constant into a
                state.proc_int_offs.add(state.pend_arg)  # by-ref INT param
                state.put(ir.Assign(argvar, ir.Lit(op[2])), state.cur)  # (t1_byref1)
                state.cur = None
            elif base == "inc_si":  # inc es:[si]: FOR-NEXT increment of a
                # by-ref int param used directly as the loop var -- implicit
                # in BASIC; consume silently, same as inc_m/inc_bp (wild
                # bmaster.exe/ifi.exe). A bare INC via ES:[SI] outside a FOR
                # is unwitnessed (by-ref `X% = X% + 1` compiles to
                # far_addm_ax_si, t1_local2) -- fail loud.
                if not (state.fors and state.fors[-1]["v"] == state.pend_arg):
                    raise ValueError(f"inc es:[si] outside a FOR at {addr:#x}")
            elif base == "dec_si":  # dec es:[si]: FOR-NEXT STEP -1 decrement
                # of a by-ref int param used as the loop var -- the
                # descending sibling of inc_si, same NEXT-side step patch-up
                # as dec_m/dec_bp (the header folded a provisional Lit(1)
                # step before this evidence was available). A bare DEC via
                # ES:[SI] outside a FOR is unwitnessed (by-ref `X% = X% - 1`
                # compiles to far_subm_ax_si) -- fail loud (wild
                # bmaster.exe/ifi.exe).
                if not (state.fors and state.fors[-1]["v"] == state.pend_arg):
                    raise ValueError(f"dec es:[si] outside a FOR at {addr:#x}")
                f = state.fors[-1]
                old = state.stmts[f["idx"]]
                state.stmts[f["idx"]] = ir.For(old.var, old.init, old.limit, ir.Lit(-1))
                f["step"] = -1
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
        if (
            kind == "orax_self"
            and state.fors
            and addr == state.fors[-1]["test"]
            and state.fors[-1].get("var_step")
        ):
            state.k = _lift_var_step_next(
                state.ops, state.k, state.fors, state.stmts, state.addrs
            )
            state.cur = None
            continue
        if (
            kind == "movax_m"
            and state.fors
            and addr == state.fors[-1]["test"]
            and state.k + 2 < len(state.ops)
            and state.ops[state.k + 1][1] == "cmpm_ax"
            and state.ops[state.k + 1][2] == state.fors[-1]["v"]
        ):
            # Variable-limit integer NEXT: `mov ax,[limit]; cmp [I%],ax; jle body`
            # (t1_fori; inc_m was consumed, step is always 1)
            f = state.fors[-1]
            jcc = state.ops[state.k + 2]
            if jcc[1] != "jcc" or jcc[2] not in (0x7E, 0x76) or jcc[3] != f["body"]:
                raise ValueError(f"int NEXT (var limit): expected JLE to body at {addr:#x}")
            state.put(ir.NextStmt(state.loc(f["v"])), state.cur)
            state.fors.pop()
            state.cur = None
            state.k += 3
            continue
        if (
            kind == "movax_bp"
            and state.fors
            and addr == state.fors[-1]["test"]
            and state.k + 2 < len(state.ops)
            and state.ops[state.k + 1][1] == "cmpm_ax_bp"
            and state.ops[state.k + 1][2] == state.fors[-1]["v"]
        ):
            # Variable-limit integer NEXT, LOCAL loop var: the bp-relative
            # mirror of the movax_m/cmpm_ax case just above (wild
            # bmaster.exe/ifi.exe, probe q_locforvarlim).
            f = state.fors[-1]
            jcc = state.ops[state.k + 2]
            if jcc[1] != "jcc" or jcc[2] not in (0x7E, 0x76) or jcc[3] != f["body"]:
                raise ValueError(f"int NEXT (var limit): expected JLE to body at {addr:#x}")
            state.put(ir.NextStmt(state.loc_local(f["v"])), state.cur)
            state.fors.pop()
            state.cur = None
            state.k += 3
            continue
        if (
            kind == "movax_bp"
            and state.fors
            and addr == state.fors[-1]["test"]
            and state.k + 3 < len(state.ops)
            and state.ops[state.k + 1][1] == "arg_ref"
            and state.ops[state.k + 1][2] == state.fors[-1]["v"]
            and state.ops[state.k + 2][1] == "far_cmpm_ax_si"
        ):
            # Variable-limit integer NEXT, BY-REF PARAM loop var: the
            # ES:[SI] mirror of the two cases just above -- the loop var
            # is itself a by-ref int parameter, addressed fresh via its own
            # arg_ref/les at every test (wild bmaster.exe/ifi.exe, probe
            # q_byrefforvar).
            f = state.fors[-1]
            jcc = state.ops[state.k + 3]
            if jcc[1] != "jcc" or jcc[2] not in (0x7E, 0x76) or jcc[3] != f["body"]:
                raise ValueError(f"int NEXT (var limit): expected JLE to body at {addr:#x}")
            state.put(ir.NextStmt(ir.Var(f"P{f['v']:02X}%")), state.cur)
            state.fors.pop()
            state.cur = None
            state.k += 4
            continue
        if (
            kind in ("cmp_mi8", "cmp_mi16", "cmp_bpi8")
            and state.fors
            and addr == state.fors[-1]["test"]
        ):
            # Integer FOR-test guard: the cmp at the open FOR's test address is the
            # integer NEXT template (`inc_m`/`addm_i8` was consumed; cmp_mi16 when
            # the limit doesn't fit a signed imm8, q_forbig). Ascending steps (the
            # default, and any literal step >= 0) test JLE/JBE; descending literal
            # steps (addm_i8 with a negative imm8) test JGE, its signed mirror
            # (q_forstepneg).
            f = state.fors[-1]
            if op[2] != f["v"]:
                raise ValueError(f"int NEXT: cmp disp mismatch at {addr:#x}")
            wantcc = (0x7D,) if f.get("step", 1) < 0 else (0x7E, 0x76)
            direct = (
                state.k + 1 < len(state.ops)
                and state.ops[state.k + 1][1] == "jcc"
                and state.ops[state.k + 1][2] in wantcc
                and state.ops[state.k + 1][3] == f["body"]
            )
            # A body beyond short-jump range uses the inverse short condition
            # over a near JMP back to the body: JG/JA skip; JMP body. Wild
            # number.exe witnesses the ascending signed JG form.
            invcc = (0x7C,) if f.get("step", 1) < 0 else (0x7F, 0x77)
            indirect = (
                state.k + 2 < len(state.ops)
                and state.ops[state.k + 1][1] == "jcc"
                and state.ops[state.k + 1][2] in invcc
                and state.ops[state.k + 2][1] == "jmp"
                and state.ops[state.k + 2][2] == f["body"]
                and state.ops[state.k + 1][3]
                == state.ops[state.k + 2][0] + 3
            )
            if not (direct or indirect):
                raise ValueError(f"int NEXT: expected JLE/JBE/JGE to body at {addr:#x}")
            state.put(
                ir.NextStmt(
                    state.loc_local(f["v"]) if kind == "cmp_bpi8" else state.loc(f["v"])
                ),
                state.cur,
            )
            state.fors.pop()
            state.cur = None
            state.k += 3 if indirect else 2
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
                # bound cells per dim: (+08,+0A), (+0E,+10), (+14,+16) --
                # rank-3 witnessed t1_dim3v
                rank = 3 if 0x16 in cells else 2 if 0x10 in cells else 1
                lows = [cells.get(0x08), cells.get(0x0E), cells.get(0x14)][:rank]
                ups = [cells.get(0x0A), cells.get(0x10), cells.get(0x16)][:rank]
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
                    for lo_c, hi_c in (
                        ((0x08, 0x0A), (0x0E, 0x10), (0x14, 0x16))[:rank]
                    )
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
                # 0A = string-descriptor elements, 06 = double (witnessed
                # t1_dblarr), so the name is typed from birth.
                tb = exe[state.ds + block + 2]
                is_str = tb == 0x0A
                suffix = "$" if is_str else "%" if tb == 0x00 else "#" if tb == 0x06 else "&" if tb == 0x02 else ""
                name = f"V{state.lay['n_static'] + state.lay['rt_blocks'].index(block)}{suffix}"
                if not all(isinstance(v, ir.Lit) for v in lows):
                    raise ValueError(
                        f"non-literal DIM lower bound at {addr:#x}: {lows}"
                    )
                state.r_arrs[block] = {
                    "name": name,
                    "rank": rank,
                    "str": is_str,
                    "esz": 8 if tb == 0x06 else 4 if tb in (0x02, 0x04, 0x0A) else 2,
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
                        prev.dynamic,
                    )  # comma list
                else:
                    state.put(
                        ir.Dim(
                            name,
                            bounds,
                            dynamic=all(
                                isinstance(v, int)
                                or isinstance(v, ir.Lit)
                                or (
                                    isinstance(v, tuple)
                                    and isinstance(v[1], (int, ir.Lit))
                                )
                                for v in bounds
                            ),
                        ),
                        state.dim_frame["start"],
                    )
                state.prev_dim_end = state.ops[state.k + 3][0]
                state.dim_frame = None
            state.cur = None
            state.k += 4
            continue
        if (
            kind == "movsi"
            and state.pend_field is not None
            and state.k + 3 < len(state.ops)
            and state.ops[state.k + 1][1] == "movdx"
            and state.ops[state.k + 2][1] == "movesdx"
            and state.ops[state.k + 3][1] == "field_as"
        ):
            # FIELD's AS-target: the width expression (a bare literal or a
            # computed one, wild hebrew.exe) already accumulated generically
            # into state.ax via the ordinary per-op dispatch above -- this
            # just closes out one FIELD entry and leaves pend_field open for
            # a possible next entry; flush_pending emits the ir.Field once
            # the next real statement starts (or EOF), same lazy-close
            # convention as the other open chains (READ/INPUT#/PRINT).
            if state.ax is None:
                raise ValueError(f"FIELD width missing at {addr:#x}")
            state.pend_field["fields"].append((state.ax, state.loc(op[2])))
            state.ax = None
            state.k += 4
            continue
        if (
            kind == "movsi"
            and op[2] in state.lay["scalars"]
            and state.k + 3 < len(state.ops)
            and state.ops[state.k + 1][1] == "movdx"
            and state.ops[state.k + 2][1] == "movesdx"
            and state.ops[state.k + 3][1] == "str2num"
        ):
            # Reading a FIELD-buffer string variable as a value (e.g.
            # `X& = CVL(V$)` where V$ was FIELD'd): the same movsi/movdx/
            # movesdx far-pointer reconstruction as FIELD's own AS-target
            # (same disp witnessed in all three wild hits), just used to
            # PUSH the variable instead of naming an assignment target.
            # Confirmed the disp is an ordinary already-tracked string
            # scalar in all three (hebrew.exe/morcalc.exe/photo.exe) --
            # movdx/movesdx don't change WHICH variable this is.
            state.sstack.append(state.loc(op[2]))
            state.k += 3
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
            elif op[2] in (0x8A, 0x96, 0xA2, 0xAE, 0xBA, 0xC6):
                # Same COLOR/VIEW cell family, uniformly +2 from the above --
                # a runtime-revision-skewed table shift (RR-COLORCELL-SHIFT):
                # no oracle probe (SCREEN mode/switch/page variants, COLOR
                # with/without KEY OFF or DEF SEG) ever produced this
                # offset, only wild bill.exe/color.exe, but all 3 cells
                # witnessed there (fg/bg/border) shift by the same +2 and
                # the semantics are otherwise identical, so it normalizes to
                # the canonical cell with no effect on emitted source.
                state.color_cells[op[2] - 2] = ir.Lit(op[3])
            elif op[2] == 0x1C:  # TB 1.0 DEF SEG = n: inline imm
                state.put(
                    ir.DefSeg(ir.Lit(op[3])), state.cur
                )  # store (1.1 uses EC sub 0x26)
                state.cur = None
            elif op[2] == 0x2E:  # short-string scratch cell: a compile-time
                state.pend_shortstr = op[3]  # -known 1-char literal packed
                # (char<<8 | len=1), staged for the `shortstr` op that
                # follows (OPEN ... FOR mode AS #n; wild nvginst.exe)
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
                # Not one of the known fixed-purpose system cells -- but
                # VAR_BASE is only the TYPICAL scalar floor, not a hard one:
                # a program using fewer of the low reserved cells can have
                # its layout solver legitimately place real scalars below
                # it (witnessed wild tamstart.exe, whose cmpax_m already
                # resolves the same disp here via state.loc with no
                # VAR_BASE gate at all -- this movm_imm path was the odd
                # one out). Defer to the solved layout before giving up.
                try:
                    var = state.loc(op[2])
                except ValueError:
                    raise ValueError(
                        f"store to unknown system cell {op[2]:#x} at {addr:#x}"
                    ) from None
                state.put(ir.Assign(var, ir.Lit(op[3])), state.cur)
                state.cur = None
            state.k += 1
            continue
        if kind == "movm_ax" and op[2] in (0x88, 0x94, 0xA0, 0xAC):
            state.color_cells[op[2]] = state.ax  # VIEW coord cell (ax leg)
            state.ax = None
            state.k += 1
            continue
        if kind == "movm_ax" and op[2] in (0x8A, 0x96, 0xA2, 0xAE):
            state.color_cells[op[2] - 2] = state.ax  # RR-COLORCELL-SHIFT, see above
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
        if kind == "addm_ax":  # int var = var + ax expression, e.g.
            var = state.loc(op[2])  # `X% = X% + 3` (no INCR fast path since the
            state.put(  # RHS isn't a bare literal-1; disp16 sibling of
                ir.Assign(var, ir.BinOp("+", var, _rgrp("+", state.ax))),
                state.cur,  # addm_ax_bp, witnessed q_addimm)
            )
            state.ax = None
            state.cur = None
            state.k += 1
            continue
        if kind == "subm_ax":  # int var = var - ax expression, e.g.
            var = state.loc(op[2])  # `X% = X% - <expr>` (subtract sibling
            state.put(  # of addm_ax; wild number.exe)
                ir.Assign(var, ir.BinOp("-", var, _rgrp("-", state.ax))),
                state.cur,
            )
            state.ax = None
            state.cur = None
            state.k += 1
            continue
        if kind == "movm_ax_bp":  # LOCAL int var = ax expression, OR --
            # bp+0 inside an open DEF FN body -- the block-form FN's own
            # integer result store, mirroring fstp_bp's float-result special
            # case (bp+0 is the frame-link word in a SUB, never a real LOCAL,
            # so this can only mean the FN result there; wild resume.exe).
            if state.fn_frame is not None and op[2] == 0:
                if state.fn_frame["block"]:
                    state.put(ir.FnResult(state.ax), state.cur)
                    state.cur = None
                else:
                    state.fn_frame["result"] = state.ax
                state.ax = None
                state.k += 1
                continue
            if state.fn_frame is None and state.proc_frame is None:
                # caller: computed (or ax-routed literal) int FN-call arg
                # staging -- the ax-register sibling of mov_bp_imm's literal
                # form above (wild resume.exe)
                state.fn_args[op[2]] = state.ax
                state.ax = None
                state.k += 1
                continue
            state.put(ir.Assign(state.loc_local(op[2]), state.ax), state.cur)
            state.ax = None
            state.cur = None
            state.k += 1
            continue
        if kind == "addm_ax_bp":  # LOCAL int var = var + ax expression, e.g.
            local = state.loc_local(op[2])  # `X% = X% + 1` (no INCR fast path
            state.put(  # for bp-relative locals -- witnessed t1_local1)
                ir.Assign(local, ir.BinOp("+", local, _rgrp("+", state.ax))),
                state.cur,
            )
            state.ax = None
            state.cur = None
            state.k += 1
            continue
        if kind == "subm_ax_bp":  # LOCAL int var = var - ax expression, the
            local = state.loc_local(op[2])  # subtract sibling of addm_ax_bp
            state.put(  # (wild horses.exe)
                ir.Assign(local, ir.BinOp("-", local, _rgrp("-", state.ax))),
                state.cur,
            )
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
        if kind == "key_macro":  # KEY n, s$: n in ax, macro on sstack
            state.put(ir.KeyDef(state.ax, state.sstack.pop()), state.cur)
            state.ax = None
            state.cur = None
            state.k += 1
            continue
        if handlers.write_ops(state, op, addr, kind):
            continue
        if kind == "shortstr":  # materialize the 1-char literal staged at
            # [002E] -- the FOR-mode-keyword form of OPEN (`OPEN f$ FOR
            # OUTPUT AS #n`) desugars its keyword to a packed 1-char string
            # at compile time instead of a real pooled literal, so this
            # doesn't go through the normal sstack push (wild nvginst.exe).
            if state.pend_shortstr is None:
                raise ValueError(f"shortstr without a staged literal at {addr:#x}")
            if state.pend_shortstr & 0xFF != 1:
                raise ValueError(f"shortstr with length != 1 at {addr:#x}")
            state.pend_mode_lit = ir.StrLit(chr(state.pend_shortstr >> 8))
            state.pend_shortstr = None
            state.k += 1
            continue
        if kind == "movsi":  # string operand by descriptor
            # VARPTR$(variable) materializes the five-byte pointer string by
            # staging the current ES:SI address in [0032]:[0030], then using
            # the packed descriptor in [002E]. Scalar and array-element
            # forms share this exact chain (probe_varptrs_scalar and
            # probe_varptrs_arr); only the address source differs.
            if (
                state.k + 8 < len(state.ops)
                and state.ops[state.k + 1][1] == "movdx"
                and state.ops[state.k + 2][1] == "movesdx"
                and state.ops[state.k + 3][1] == "movm_imm"
                and state.ops[state.k + 3][2] == 0x2E
                and state.ops[state.k + 4] == (state.ops[state.k + 4][0], "movm_es", 0x32)
                and state.ops[state.k + 5] == (state.ops[state.k + 5][0], "movm_si", 0x30)
                and state.ops[state.k + 6][1] == "shortstr"
                and state.ops[state.k + 7][1] == "movsi"
                and state.ops[state.k + 8][1] == "strassign"
            ):
                src = state.slot_info.get(op[2])
                if src is not None:
                    if src["rank"] != 1:
                        raise ValueError(f"VARPTR$ rank-{src['rank']} array at {addr:#x}")
                    arg = ir.ArrayRef(src["name"], (ir.Lit(src["lo"][0]),))
                else:
                    arg = state.loc(op[2])
                state.put(
                    ir.Assign(
                        state.loc(state.ops[state.k + 7][2]),
                        ir.Call("VARPTR$", (arg,)),
                    ),
                    state.cur,
                )
                state.cur = None
                state.k += 9
                continue
            nxt = state.ops[state.k + 1][1:] if state.k + 1 < len(state.ops) else None
            d = cast(int, op[2])
            if nxt == ("local_arr_free",):  # implicit runtime cleanup of a
                # LOCAL DYNAMIC array's heap block at SUB exit -- no BASIC
                # source spelling, so it's silently dropped (q_localarr)
                if d not in state.r_arrs:
                    raise ValueError(
                        f"LOCAL array free of unknown handle {d:#x} at {addr:#x}"
                    )
                state.k += 2
                continue
            if nxt == ("rt", 0x9C):  # push (var desc, static string-array
                # element at a constant index, or pooled literal)
                is_local = d in state.lay["strs"] or any(
                    a["str"] and a["base"] <= d < a["base"] + a["esz"] * a["count"]
                    for a in state.arrs
                )
                state.sstack.append(
                    state.loc(d) if is_local else state._pool_str(d)
                )
                state.k += 2
                continue
            if nxt == ("spush_bp",):  # push string param [bp+si]: DEF FN body
                assert state.fn_frame is not None  # (witnessed t1_fnstr)
                state.fn_frame["param_offs"].add(d)
                state.fn_frame["str_offs"].add(d)
                state.sstack.append(ir.Var(f"P{d:02X}$"))
                state.k += 2
                continue
            if nxt == ("strassign_bp",):  # pop-store string to [bp+si]
                if state.fn_frame is not None:  # FN result desc at [bp+0]
                    if d != 0:
                        raise ValueError(
                            f"string store to [bp+{d}] in DEF FN body at {addr:#x}"
                        )
                    state.fn_frame["str"] = True
                    if state.fn_frame["block"]:  # FNx$ = expr statement
                        state.put(ir.FnResult(state.sstack.pop()), state.cur)
                        state.cur = None
                    else:  # single-line body expr
                        state.fn_frame["result"] = state.sstack.pop()
                else:  # caller: stage a string FN-call arg
                    state.fn_args[d] = state.sstack.pop()
                state.k += 2
                continue
            if nxt == ("strassign",):  # pop-assign into a string var
                if state.pend_input is not None:  # ... as an INPUT's string read
                    state._input_target(state.loc(d), is_str=True)
                elif (
                    state.sstack and state.sstack[-1] is _FREAD
                ):  # INPUT# string target
                    state.sstack.pop()
                    state._fread_target(state.loc(d))
                elif state.pend_getstr is not None:
                    num, count = state.pend_getstr
                    state.pend_getstr = None
                    state.put(ir.GetString(num, count, state.loc(d)), state.cur)
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
            if nxt == ("palette_using",):
                if state.pend_es is None:
                    raise ValueError(f"PALETTE USING without ES at {addr:#x}")
                a = state.r_arrs[state.pend_es]
                if a.get("str") or a.get("esz") != 2 or a["rank"] != 1:
                    raise ValueError(
                        f"PALETTE USING non-INTEGER rank-{a['rank']} array at {addr:#x}"
                    )
                ref = ir.ArrayRef(
                    a["name"], (ir.Lit(d // 2 + a["lo"][0]),)
                )
                state.pend_es = None
                state.put(ir.PaletteUsing(ref), state.cur)
                state.cur = None
                state.k += 2
                continue
            if (
                state.k + 3 < len(state.ops)
                and state.ops[state.k + 1][1] == "movdx"
                and state.ops[state.k + 2][1] == "movesdx"
                and state.ops[state.k + 3][1] == "palette_using"
            ):
                ref = state.loc(d)
                if not isinstance(ref, ir.ArrayRef):
                    raise ValueError(f"PALETTE USING non-array operand at {addr:#x}")
                a = next((a for a in state.arrs if a["name"] == ref.name), None)
                if a is None or a.get("str") or a.get("esz") != 2 or a["rank"] != 1:
                    raise ValueError(f"PALETTE USING array mismatch at {addr:#x}")
                state.put(ir.PaletteUsing(ref), state.cur)
                state.cur = None
                state.k += 4
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
        if kind == "moves_bp":  # mov es,[bp+d8]: LOCAL DYNAMIC array's
            # element segment, the LOCAL-frame sibling of moves_m
            if op[2] not in state.r_arrs:
                raise ValueError(
                    f"mov es from non-array LOCAL cell {op[2]:#x} at {addr:#x}"
                )
            state.pend_es = op[2]
            state.k += 1
            continue
        if kind == "far_movm_ax_disp":
            # `$DYNAMIC` constant-bound numeric arrays use a direct ES:[disp]
            # store for constant subscripts, rather than the usual indexed
            # ES:[SI] path (witnessed t1_dynconstnum).  The displacement is
            # the byte offset within a 2-byte integer array element stream.
            if state.pend_es is None:
                raise ValueError(f"direct far array store without ES at {addr:#x}")
            rec = state.r_arrs.get(state.pend_es)
            if rec is None or rec.get("str"):
                raise ValueError(f"direct far array store type mismatch at {addr:#x}")
            if op[2] & 1:
                raise ValueError(f"unaligned direct far array store at {addr:#x}")
            idx = op[2] // 2 + rec["lo"][0]
            state.put(
                ir.Assign(ir.ArrayRef(rec["name"], (ir.Lit(idx),)), state.ax),
                state.cur,
            )
            state.ax = None
            state.pend_es = None
            state.cur = None
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
