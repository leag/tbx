"""decode_user_code: the top-level decode orchestrator."""

from __future__ import annotations
import struct
from dataclasses import dataclass, fields, is_dataclass, replace
from typing import Any, cast

from tbx import ir
from tbx.decode0.const import (
    ARR_BLOCK,
    VAR_BASE,
    _FREAD,
    _JCC_RELOP,
    _JCC_RELOP_STR,
    _JCC_RELOP_STR_TRUE,
    _JCC_RELOP_TRUE,
    _NEGATE_REL,
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
    _find_jmps_back,
    _fold_body_ifgotos,
    _fold_if,
    _jump_targets,
    _lift_midblock_troff,
    _lift_next,
    _lift_var_step_next,
    _resolve_targets,
    _same_code_offset,
)
from tbx.decode0.matchers import (
    match_bool_bare_term1,
    match_for_header,
    match_loose_for_header,
    match_proc_body,
)
from tbx.decode0.rename import _slot, _str_lit, canonical_rename
from tbx.decode0.cursor import DecodeDiagnostics, OpCursor
from tbx.decode0.events import DecodedEvent, EventLog, reconcile
from tbx.decode0.frames import (
    BoolTerm,
    FnFrame,
    ForFrame,
    DimFrame,
    IfFrame,
    LoopFrame,
    PendingFold,
    ProcFrame,
)
from tbx.decode0.statement_log import RecordedStatements, editing, replay
from tbx.decode0.addresses import AddressOwnership
from tbx.decode0.control_graph import ControlGraph
from tbx.decode0.state_parts import (
    STATE_VIEWS,
    ControlState,
    ExprState,
    ImageState,
    LayoutState,
    MachineState,
    OutputState,
)

# Word count `local_init` reserves for a LOCAL DYNAMIC array's descriptor
# template -- a fixed size regardless of rank or element type (witnessed
# identical for rank-1 and rank-2 probes, q_localarr/q_locarr3); only 5 of
# the 30 words are ever written (handle, type/rank, esize, one bound pair),
# the rest is dead padding sized for the worst case the runtime supports.
_LOCAL_ARR_WORDS = 30


def _logical_condition(value):
    """Convert register-folded logical values back into condition IR.

    Boolean groups use the integer register combiner, so their intermediate
    representation is a ``BinOp`` even when every leaf is a relation.  At a
    direct branch gate that value cannot be arithmetic: preserving the logical
    tree here retains the source grouping and keeps numeric bitwise values out
    of the conversion (probe_string_nested_and_or_block; wild grdscn.exe).
    """
    if isinstance(value, (ir.RelOp, ir.LogOp)):
        return value
    if isinstance(value, ir.Group):
        inner = _logical_condition(value.inner)
        return ir.Group(inner) if inner is not None else None
    if isinstance(value, ir.BinOp) and value.op in ("=", "<>", "<", "<=", ">", ">="):
        return ir.RelOp(value.op, value.lhs, value.rhs)
    if isinstance(value, ir.BinOp) and value.op in ("AND", "OR"):
        lhs, rhs = _logical_condition(value.lhs), _logical_condition(value.rhs)
        if lhs is not None and rhs is not None:
            # The integer fold has no node for the explicit outer parens in
            # `(A OR B) AND C`; retain the grouping needed to regenerate its
            # distinct short-circuit template (t1_nestedbool).
            if value.op == "AND" and isinstance(value.lhs, ir.BinOp) and value.lhs.op == "OR":
                lhs = ir.Group(lhs)
            if value.op == "AND" and isinstance(value.rhs, ir.BinOp) and value.rhs.op == "OR":
                rhs = ir.Group(rhs)
            return ir.LogOp(value.op, lhs, rhs)
    return None


@dataclass
class DecodeState:
    """Mutable register file for :func:`decode_user_code` -- every field is a
    persistent decode-loop variable, initialized in the setup block before the
    main dispatch loop and shared by the handler modules."""

    addrs: Any = None
    arrs: Any = None
    ax: Any = None
    bchk_subs: Any = None
    bchk_bp: Any = None
    block_if_addrs: Any = None
    bx: Any = None
    cases: Any = None
    cc_hooks: Any = None
    cint_round: Any = None
    color_cells: Any = None
    commits: Any = None
    event_log: Any = None
    cur: Any = None
    cx: Any = None
    desc_disps: Any = None
    dia: Any = None
    dim_frame: dict[str, Any] | None = None
    discard_strs: Any = None
    direct_bool_gate: bool = False
    direct_bool_logical: bool = False
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
    pending_ifs: Any = None
    fold_plan: Any = None
    k: Any = None
    lay: Any = None
    local_dim_frame: dict[str, Any] | None = None
    main_start: Any = None
    metas: Any = None
    nfn: Any = None
    n_local_arrs: int = 0
    fwd_inline_offs: Any = None
    inline_procs: Any = None
    nsub: Any = None
    seg_metas: Any = None
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
    proc_long_offs: Any = None
    proc_dbl_offs: Any = None
    proc_str_offs: Any = None
    reg_logical_results: Any = None
    reg_spills: Any = None
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
    cursor: OpCursor | None = None
    diagnostics: DecodeDiagnostics | None = None
    image: ImageState | None = None
    machine: MachineState | None = None
    expr: ExprState | None = None
    layout_state: LayoutState | None = None
    control: ControlState | None = None
    output: OutputState | None = None

    def __post_init__(self) -> None:
        for name, view in STATE_VIEWS.items():
            setattr(self, name, view(self))

    def begin(self, ops) -> None:
        """Install the operation stream and open the cursor over it.

        Stream, index, and cursor have to agree from the first operation on,
        so they are established together rather than as three assignments a
        caller could get out of order.
        """
        self.ops = ops
        self.k = 0
        self.cursor = OpCursor(ops)
        self.diagnostics = self.diagnostics or DecodeDiagnostics()

    def advance(self, count: int = 1) -> None:
        """Commit operation consumption through the cursor.

        This is how a handler reports what it consumed; nothing else may
        write ``k``.  A state built without :meth:`begin` has no cursor --
        isolated handler tests construct one that way -- and then the index
        moves on its own.
        """
        self.seek(self.k + count)

    def seek(self, index: int) -> None:
        """Commit consumption up to an absolute operation index.

        The relative :meth:`advance` is the common case; a lookahead helper
        that computes where it stopped reports that position here instead of
        assigning ``k``, so the cursor still witnesses the whole window.
        """
        if self.cursor is None:
            self.k = index
            return
        self.cursor.sync(self.k)
        self.cursor.sync(index)
        self.k = self.cursor.index

    def error(self, message: str, *, component: str | None = None) -> ValueError:
        """Create a fail-loud error enriched with the current decode context."""
        if self.diagnostics is None:
            return ValueError(message)
        self.diagnostics.component = component
        context = self.diagnostics.report()
        return ValueError(f"{message} [{context}]")

    def validate_ownership(self) -> None:
        """Verify that compatibility views still alias this live state."""
        for name in STATE_VIEWS:
            view = getattr(self, name)
            if view is None or view._owner is not self:
                raise ValueError(f"decoder state view {name!r} is detached")

    def pool_lit(self, disp):
        raw = struct.unpack_from("<H", self.exe, self.dsd + disp)[0]
        # A signed negative literal is materialized with runtime arithmetic
        # (`-1` becomes `FLD1; FCHS` / `MOV AX,1; NEG AX`), whereas an
        # unsigned 16-bit token such as `&HFFFF` lives in the integer pool
        # and is loaded with FILD.  Retain that raw token spelling: treating
        # it as the numerically equivalent ``Lit(-1)`` changes the code
        # template (tbd73's FNCurdisplay REG masks).
        return ir.HexLit(raw) if raw & 0x8000 else ir.Lit(raw)

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
            locs = self.proc_frame.locals
            if locs is None or bp_off not in locs:
                raise ValueError(f"[bp+{bp_off}] outside the open LOCAL frame")
            self.touch_local(bp_off)
            return ir.Var(locs[bp_off])
        if self.fn_frame is not None:
            locs = self.fn_frame.locals
            if locs is not None and bp_off in locs:
                self.touch_local(bp_off)
                return ir.Var(locs[bp_off])
            # Not a declared LOCAL: an integer-typed DEF FN param read via the
            # ax-register path (fp_bp handles the FP-typed equivalent) --
            # params aren't always the fixed 4-byte-stride slots a
            # float-only FN uses; an all-integer param list packs 2 bytes
            # apiece starting right after the result cell (wild resume.exe).
            self.fn_frame.param_offs.add(bp_off)
            self.fn_frame.int_offs.add(bp_off)
            return ir.Var(f"P{bp_off:02X}%")  # suffix must match the `params`
            # tuple's own spelling below, or rename.py sees two "different"
            # variables for the one param (byte-exact needs the declared
            # name and every body reference to agree)
        raise ValueError(f"[bp+{bp_off}] outside the open LOCAL frame")

    def touch_local(self, bp_off):
        """Record that the body really referenced this frame slot.

        A LOCAL FOR reserves unused step/limit temp words that can only be
        located positionally, at the frame tail. Rather than delete a guessed
        offset mid-walk, the FOR paths just flag `has_local_for` and
        `proc_ret`/`fn_ret` call `_retire_for_temps`, which drops tail words
        only if they were never touched -- the whole body's evidence is in by
        then, which a single forward pass cannot have at the FOR header.
        """
        frame = self.proc_frame if self.proc_frame is not None else self.fn_frame
        if frame is not None:
            frame.touched.add(bp_off)

    def close_ifs(self, addr) -> None:
        """Close every open inline-IF body whose skip target is `addr`, folding
        each into an `ir.IfInline`.

        Normally driven from the top of the dispatch loop. `select_case.py` also
        calls it just before it snapshots an arm, because an inline IF that is
        the LAST statement of a CASE arm skips to the arm-close jmp -- and
        `select_case.step` runs BEFORE this point in the loop, so the arm would
        otherwise be folded away with the IF's body still open (wild tbd73.exe,
        TBW73.INC:716).
        """
        while self.ifs and addr == self.frame_event(self.ifs[-1]).payload.target:
            fr = self.ifs.pop()
            self.flush_pending()
            # The region is complete here and its extent is only knowable here
            # -- the list's length at this moment. Folding it is a separate
            # question, answered when the construct that owns it closes.
            start = self.frame_start(fr.seq, fr.idx)
            self.pending_ifs.append(
                PendingFold(
                    seq=fr.seq,
                    start=start,
                    stop=len(self.stmts),
                    # The addresses the eager fold would have removed by now.
                    # A later recognizer that asks "is this address a statement
                    # start" means the folded list, and this is what it no
                    # longer holds -- captured here because a body's addresses
                    # are stable, while its indices are not.
                    addrs=frozenset(a for a in self.addrs[start:] if a is not None),
                )
            )
            # The same region, kept past the fold that consumes it. What the
            # splice records is where it *landed*, and once folding is deferred
            # that is no longer where the walk saw it -- everything folded in
            # between has moved it. This is the walk's own account, and the
            # only one a prediction from the record can be checked against.
            self.control.fold_plan.append((start, len(self.stmts)))

    @property
    def folded_away(self) -> frozenset:
        """Addresses inside a region that is queued but not yet folded.

        The eager fold had removed these from `addrs` by the time any later
        recognizer looked. Deferring keeps them there, so a recognizer that
        asks whether an address is a statement start has to be told which ones
        only look like one because the fold has not run yet.
        """
        return frozenset().union(frozenset(), *(fr.addrs for fr in self.pending_ifs))

    @property
    def fold_products(self) -> frozenset:
        """Addresses a queued region will carry once it folds.

        The other half of `folded_away`: the fold replaces the body with one
        `IfInline` standing at the branch's own address, so that address is a
        statement start under the eager fold and is not in the list yet here.
        """
        return frozenset(
            self.frame_event(fr).address
            for fr in self.pending_ifs
            if self.frame_event(fr).address is not None
        )

    def statement_index(self, address) -> int | None:
        """Where `address` starts a statement once the queued folds have run.

        The eager fold answered this by construction, and every recognizer
        that asks -- "is this backward jmp's target a statement, and which
        one?" -- means the folded list. Deferring leaves the list halfway
        between the two states, so the answer is composed: what stands there
        now, minus the bodies a queued region will absorb, plus the statements
        those regions will leave behind.

        A queued region's own position is a live one. Nothing below it has
        folded yet, so its recorded `start` is where its `IfInline` lands.
        """
        for fr in self.pending_ifs:
            if self.frame_event(fr).address == address:
                return fr.start
        if address in self.folded_away:
            return None
        return self.addrs.index(address) if address in self.addrs else None

    def shift_pending(self, index: int, delta: int) -> None:
        """Move queued fold regions across a splice at `index`.

        A queued region is a pair of list positions, so a statement inserted
        below one moves the body it names. The eager fold never had to know:
        by the time a loop lift ran, the region was already a single statement.

        The bounds are half-open and move differently at their own index. An
        insert *at* `start` pushes the body's first statement down, so the
        region follows it. An insert *at* `stop` lands after the body's last
        statement, outside the region, and must not stretch it -- which is
        exactly where a `DO` goes when a loop begins right after an inline IF
        (wild state.exe, the IF at 0xeaca, whose body took in the `DO`).
        """
        for fr in self.pending_ifs:
            if fr.start >= index:
                fr.start += delta
            if fr.stop > index:
                fr.stop += delta

    def drain_folds(self, limit: int = 0) -> None:
        """Fold every queued inline-IF region that lies at or after ``limit``.

        Called when a construct closes, so the regions inside it are folded
        before it takes its snapshot: the arm close, the procedure return, and
        the end of the walk. A region left open past its enclosing construct
        would be snapshotted still flat, which is what the eager fold existed
        to prevent.

        Queue order is fold order. A region nested inside another closes first
        and so is queued first, and two closing at the same address were queued
        innermost-first by `close_ifs` -- both give the same rule. Each fold
        collapses its region to one statement, so the regions still queued move
        by what it removed.

        Every position here is in the coordinates the regions were *recorded*
        in, and `shifts` is keyed the same way -- a fold's boundary is where
        the region ended when it closed, not where the splice landed. The two
        agree for the first fold in a batch and diverge from there, and mixing
        them makes a fold look as though it precedes a region that is really
        nested inside it, so the enclosing body starts too early (wild
        invoice.exe, the IF at 0xd316: 11 statements folded where the walk saw
        8, the three extra being the ones its own inner regions had taken).
        """
        with editing(self.stmts, "close_ifs"):
            draining = [fr for fr in self.pending_ifs if fr.start >= limit]
            self.pending_ifs = [fr for fr in self.pending_ifs if fr.start < limit]
            shifts: list[tuple[int, int]] = []

            def shifted(position: int) -> int:
                return position - sum(size for at, size in shifts if position >= at)

            for fr in draining:
                opened = self.frame_event(fr)
                start, stop = shifted(fr.start), shifted(fr.stop)
                body = tuple(self.stmts[start:stop])
                if not body:
                    raise ValueError(
                        f"empty inline-IF body at {opened.payload.target:#x}"
                    )
                for st, ad in zip(body, self.addrs[start:stop]):
                    if ad is not None:  # retain leaf/body addrs before they drop
                        self.stmt_addr.claim(st, ad)  # the fold discards them
                body = _fold_body_ifgotos(
                    body, opened.payload.target, self.stmt_addr
                )  # AFTER the
                # addr retention: the fold nests the tail statements, and their (and
                # the consumed IfGoto's) addrs must stay visible to the line table
                self.stmts[start:stop] = [ir.IfInline(opened.payload.cond, body)]
                self.addrs[start:stop] = [opened.address]
                shifts.append((fr.stop, (stop - start) - 1))

    def frame_event(self, frame):
        """The branch event an open frame is: the record, not a copy of it.

        A frame is stored as the `seq` of the event that recognised it, so the
        condition it folds, the address it starts at and the target it closes
        on are all read from the log rather than carried alongside it.
        """
        return self.events[frame.seq]

    def frame_start(self, seq: int, idx: int) -> int:
        """Where a body that opened at event ``seq`` begins, from the record.

        The list's length when that event was recorded, replayed from the
        statement edits stamped up to it. The walk also noted the length at
        the time -- ``idx`` -- and the two must agree; the check is what makes
        reading it from the record a fact rather than a hope.

        Taken as two numbers rather than as a frame because the callers no
        longer share a type: an inline IF's frame is still a dict, a
        procedure's and a SELECT arm's are not.
        """
        from tbx.decode0.control_graph import _length_at

        start = _length_at(self.stmts.edits, seq)
        if start != idx:
            raise ValueError(
                f"fold region start {start} from the record disagrees with "
                f"the frame's own {idx}"
            )
        return start

    def open_tail_if(self, target, cond) -> bool:
        """If `target` is the open procedure's own epilogue, open an inline-IF
        body for `cond` and return True; otherwise return False and leave the
        state untouched.

        The single-line `IF cond THEN <stmt>` dispatch pair (`jcc +3; e9 SKIP`)
        normally lifts to `IF <negated> THEN <line>` -- the skip address named as
        a GOTO target. That needs the skip address to BE a statement, which it is
        for every IF followed by more code. When the IF is the LAST statement of
        a SUB/DEF FN body, the skip instead lands on the epilogue (the
        `proc_ret`/`fn_ret`, or the LOCAL-string teardown ahead of it -- see
        `exit_entry`), which is not a statement and never can be: `END SUB`
        carries no line number. Opening an `ifs` body keeps it inline and needs
        no target at all. The `ifs`-close loop fires on the epilogue address
        BEFORE the proc_ret/fn_ret handler runs, so the body folds normally.

        Callers pass the SOURCE polarity of the condition (the dispatch pair's
        jcc tests its negation -- the skip), since only they know which relop map
        produced it.

        The same reasoning covers a SELECT CASE arm: an IF closing an arm skips
        to the arm's trailing `jmp END SELECT`, which is glue, not a statement.
        `cases[-1].body_jmp` is that address while the arm is open (and equals
        the END SELECT for a flow-through final arm).

        Witnessed by wild tbd73.exe: TBW73.INC:634 (`IF numrecs - recpos + 1 < i
        THEN barpos = j - 1` closing `SUB Drawlist`, `jump target 0xcdc4`) for
        the epilogue case -- fixture t1_iftaillast -- and TBW73.INC:716
        (`IF i <> numrecs THEN CALL Drawlist(...)` closing `CASE CHR$(71)`,
        `jump target 0xd367`) for the arm case -- fixture t1_iftailarm.
        """
        frame = self.proc_frame if self.proc_frame is not None else self.fn_frame
        ends = set()
        if frame is not None:
            ends.add(frame.exit)
            ends.add(frame.teardown_entry)
        if self.cases and self.cases[-1].body_jmp is not None:
            ends.add(self.cases[-1].body_jmp)
        if target not in ends:
            return False
        self.flush_pending()
        event = self.branch(
            "if", template="inline_if_target", target=target,
            address=self.cur, cond=cond,
        )
        self.ifs.append(IfFrame(seq=event.seq, idx=len(self.stmts)))
        self.cur = None
        return True

    def loc_local_str(self, bp_off):
        """Resolve a four-byte STRING LOCAL first exposed by INT 9E/A2.

        LOCAL initialization zero-fills an untyped word range.  A string
        access retypes the first two-word pair and removes its phantom high
        word, mirroring fp_bp's first-touch SINGLE refinement.
        """
        frame = self.proc_frame if self.proc_frame is not None else self.fn_frame
        if frame is None:
            raise ValueError(f"string [bp+{bp_off}] outside an open local frame")
        locs = frame.locals
        if locs is None or bp_off not in locs:
            raise ValueError(f"string [bp+{bp_off}] outside the open LOCAL frame")
        self.touch_local(bp_off)
        name = locs[bp_off]
        if name.endswith("%"):
            name = name[:-1] + "$"
            locs[bp_off] = name
            locs.pop(bp_off + 2, None)
        elif not name.endswith("$"):
            raise ValueError(f"[bp+{bp_off}] already has non-string LOCAL type")
        return ir.Var(name)

    def flush_pending(self):
        """A trailing-';' print has no flush vector: the chain is proven
        closed only when the next statement completes, so finalize lazily with
        newline=False. (Consecutive same-leg prints merge -- byte-identical.)
        INPUT# target chains end the same way: the last store has no
        terminator, so they too finalize on the next completed statement (with a
        forced flush at any [0060] store so adjacent statements never merge).

        A chain closes late but is still a decoder decision, so each one lands
        through `commit` and records its event like any other statement."""
        with editing(self.stmts, "flush_pending"):
            if self.pend_dataread is not None:
                pr, self.pend_dataread = self.pend_dataread, None
                if not pr["targets"]:
                    raise ValueError("READ chain closed without any stored target")
                self.commit(ir.Read(tuple(pr["targets"])), pr["start"])
            if self.pend_filein is not None:
                pf, self.pend_filein = self.pend_filein, None
                if not pf["targets"]:
                    raise ValueError("INPUT# chain closed without any stored target")
                self.commit(
                    ir.InputFile(pf["num"], tuple(pf["targets"])), pf["start"]
                )
                self.pend_fnum = None
            if self.pend_field is not None:
                pfd, self.pend_field = self.pend_field, None
                if not pfd["fields"]:
                    raise ValueError("FIELD chain closed without any AS-entry")
                self.commit(ir.Field(pfd["fnum"], tuple(pfd["fields"])), pfd["start"])
            if self.pend_print is not None:
                pp, self.pend_print = self.pend_print, None
                if pp.mode == "write":  # WRITE / WRITE# has no trailing-';' form:
                    stmt = ir.Write(tuple(pp.items), file=pp.file)
                elif pp.mode == "lprint":  # trailing-';' LPRINT: closed by
                    # the next completed statement, like console PRINT (witnessed
                    # t1_lpusing -- an LPRINT USING follows with no B9 between)
                    stmt = ir.Lprint(
                        tuple(pp.items),
                        newline=False,
                        commas=_pp_commas(pp),
                    )
                else:
                    stmt = ir.Print(
                        tuple(pp.items),
                        newline=False,
                        file=pp.file,
                        commas=_pp_commas(pp),
                    )
                self.commit(stmt, pp.start)
            if self.pend_using is not None:
                pu, self.pend_using = self.pend_using, None
                self.commit(
                    ir.PrintUsing(
                        pu["fmt"],
                        tuple(pu["values"]),
                        file=pu["file"],
                        newline=False,
                        lprint=pu.get("lprint", False),
                    ),
                    pu["start"],
                )

    def put(self, stmt, addr):
        self.flush_pending()
        self.commit(stmt, addr)

    def commit(self, stmt, addr):
        """Append a decided statement and record the event that says so.

        The one way into the statement list. `put` closes any pending chain
        first and lands here; `flush_pending` is what closes those chains, and
        lands here too. A statement that reached the list any other way would
        be a decision with nothing in the log accounting for it, which is
        exactly what the control-flow pass cannot replay.

        Record what was decided, with the address still unresolved. Folding
        rewrites `stmts` in place afterwards; the log is the only account of
        what the decoder actually committed.
        """
        output = self.output
        assert output is not None
        output.stmts.append(stmt)
        output.addrs.append(addr)
        if output.event_log is None:
            output.event_log = EventLog()
        output.event_log.commit(stmt, addr)

    def reconstruct(self, index, stmt) -> None:
        """Insert a statement finalization derived from a layout or pool fact.

        DIM, DATA, OPTION BASE, COMMON and DEFtype own no code: they are
        recovered from array bookkeeping, the data pool and the error-trap
        line table, so nothing was decoded for them and their address is
        `None`. Recording the reconstruction is what keeps them apart from the
        statements folding builds -- both used to arrive in the program with
        no event at all, under the one name "synthesized".
        """
        output = self.output
        assert output is not None
        output.stmts.insert(index, stmt)
        output.addrs.insert(index, None)
        if output.event_log is None:
            output.event_log = EventLog()
        output.event_log.reconstruct(stmt)

    def patch(self, index, stmt) -> None:
        """Revise an already-committed statement, recording the revision.

        Some statements compile to two runtime calls -- a LOCATE's cursor
        argument, a FOR's real step, a second DIM joining the first as a comma
        list -- so the handler that sees the second one rewrites what the
        first committed. The list edit alone leaves the log describing a
        statement the program does not contain; the event says what replaced
        it. Callers keep their own `editing` scope, which is what attributes
        the list edit to the pass.
        """
        output = self.output
        assert output is not None
        previous = output.stmts[index]
        output.stmts[index] = stmt
        if output.event_log is None:
            output.event_log = EventLog()
        output.event_log.supersede(previous, stmt)

    def arrive(self, address) -> None:
        """Record reaching `address`, when some recorded branch targets it.

        Called from the dispatch loop rather than from the fold, on purpose:
        the moment a region ends has to stay in the record once folding moves
        out of the walk. The log decides whether the address is one a branch is
        waiting for, so this stays a plain observation of where the walk is.
        """
        output = self.output
        assert output is not None
        if output.event_log is None:
            output.event_log = EventLog()
        if self.ifs and address == self.frame_event(self.ifs[-1]).payload.target:
            # A trailing-';' PRINT closing the body is decoded before this
            # boundary but only materializes when something flushes it --
            # `close_ifs` itself, a line later. Flushing here puts it in the
            # list before the arrival is stamped, so the recorded moment is the
            # one the statement belongs to. Same call, same address, one line
            # earlier: `close_ifs` re-flushes into an empty chain (wild be.exe,
            # whose `IF ... THEN PRINT "Approximately ";` body is exactly this).
            self.flush_pending()
        output.event_log.arrive(address)

    def region(self, kind: str, *, start, end, detail=None):
        """Record a construct's extent alongside the statements it spans.

        Returns the event, for the same reason a branch's is returned: a
        construct that owns a body is identified by it, and where that body
        begins in the list is read back from the record at that event rather
        than noted on the recognizer's own frame.
        """
        output = self.output
        assert output is not None
        if output.event_log is None:
            output.event_log = EventLog()
        return output.event_log.region(kind, start=start, end=end, detail=detail)

    def branch(
        self, frame: str, *, template, target, address=None, cond=None, block=False
    ):
        """Record a branch this handler recognised, and return the event.

        Emitting is deliberately separate from committing: the statement list
        does not change, so no golden moves, but the control graph can now see
        a decision the handler used to make invisibly. The event is returned
        because a frame that opens a body is now *identified* by it -- what
        `close_ifs` folds comes from the record, not from a copy the walk keeps.
        """
        output = self.output
        assert output is not None
        if output.event_log is None:
            output.event_log = EventLog()
        return output.event_log.branch(
            frame,
            template=template,
            target=target,
            address=address,
            cond=cond,
            block=block,
        )

    @property
    def events(self) -> tuple[DecodedEvent, ...]:
        """The commit-time event log, in emission order."""
        log = self.output.event_log if self.output is not None else None
        return () if log is None else log.frozen()

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
        self.put(
            ir.LineInput(pi["prompt"], ref, pi.get("file"), semi=pi["semi"]),
            pi["start"],
        )
        self.pend_line_input = None

    # decode a pooled string literal at descriptor `desc`; desc and ss_base are ints
    # wherever a string literal is present (else this is unreached)
    def _pool_str(self, desc: object) -> ir.StrLit:
        return _str_lit(self.exe, self.dsd, cast(int, desc), cast(int, self.ss_base))

    def vdisp(self, node):  # placeholder Var -> DS displacement
        return int(node.name[1:].rstrip("%&#!"), 16)


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


def _drop_local_descriptor_initializers(state, frame, span, addr) -> None:
    """Remove compiler metadata writes that preceded a LOCAL DIM bracket."""
    o = state.output
    locs = frame.locals
    assert locs is not None
    cell_names = {locs[x] for x in span}
    start = frame.idx
    kept = list(zip(o.stmts[:start], o.addrs[:start]))
    for stmt, stmt_addr in zip(o.stmts[start:], o.addrs[start:]):
        refs, _ = _region_refs(stmt)
        if not cell_names.intersection(refs):
            kept.append((stmt, stmt_addr))
            continue
        if not (
            isinstance(stmt, ir.Assign)
            and isinstance(stmt.target, ir.Var)
            and stmt.target.name in cell_names
            and isinstance(stmt.value, ir.Lit)
        ):
            raise ValueError(f"used LOCAL array descriptor cells at {addr:#x}")
    with editing(o.stmts, "drop_local_descriptor_initializers"):
        o.stmts[:] = [stmt for stmt, _ in kept]
    o.addrs[:] = [stmt_addr for _, stmt_addr in kept]


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
    o = state.output
    regions: list[tuple[int, list[str], list[str]]] = []
    for i, s in enumerate(o.stmts):
        if isinstance(s, ir.SubDef):
            vs, ars = _region_refs(s.body)
            # A SUB's formals are its own scope: two SUBs whose params share a
            # bp offset get the same P-name, which must not read as a cross-
            # region (SHARED) reference (q_fwd).
            vs = [v for v in vs if v not in s.params]
            # ...and the same for its ARRAY formals, spelled `NAME(1)` in the
            # signature but referenced bare: two SUBs relaying the same array
            # parameter share a bp offset and so the same P-name, which must
            # not read as a cross-region SHARED reference (probe t1_arrfwd).
            own = {p[: p.index("(")] for p in s.params if p.endswith("(1)")}
            ars = [a for a in ars if a not in own]
            # ...and the same, again, for its declared LOCALs. A LOCAL is named
            # from its FRAME offset (`L52%`, `L6E$`), so two SUBs whose locals
            # land on the same offset share a name -- and TWO SUBs declaring
            # `LOCAL done, mloop, ans$, ans1$` is the ordinary case, not a rare
            # one. Without this the cross-region test reads each SUB's own
            # locals as SHARED and synthesizes a declaration that REPEATS them,
            # which TB rejects outright: `Error 463: Duplicate variable
            # declaration` (wild tbd73.exe -- TBW73.INC:440 and 551, whose
            # `Makevmenu`/`Makehmenu` locals collide four ways, blocking the
            # whole program's recompile). Array locals are spelled `NAME()` in
            # the LOCAL statement, matching how `ars` names them.
            #
            # Only the SHARED synthesis is filtered: a genuinely SHARED
            # variable is never also declared LOCAL, so nothing legitimate can
            # be hidden by this (fixture t1_twosublocal).
            own_loc = {
                n for b in s.body if isinstance(b, ir.Local) for n in b.names
            }
            vs = [v for v in vs if v not in own_loc]
            ars = [a for a in ars if f"{a}()" not in own_loc]
            regions.append((i, vs, ars))
    main_stmts = [s for s in o.stmts if not isinstance(s, ir.SubDef)]
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


def _scalar_param_name(state, off) -> str:
    """Spell one by-ref SUB parameter slot from the type evidence its body
    accesses left behind. Shared by the all-scalar and the mixed
    scalar/array signature paths, which must agree: the declared header and
    every body reference have to name the same variable or rename.py letters
    them apart (byte-exact needs both spellings identical)."""
    c = state.control
    if off in c.proc_str_offs:
        return f"P{off:02X}$"
    if off in c.proc_int_offs:
        return f"P{off:02X}%"
    if off in c.proc_long_offs:
        return f"P{off:02X}&"
    if off in c.proc_dbl_offs:
        return f"P{off:02X}#"
    return f"P{off:02X}"


def _retire_for_temps(frame, locs) -> None:
    """Drop a LOCAL FOR's unused [step, limit] temp words from the frame table.

    Runs at proc_ret/fn_ret, once the WHOLE body is decoded, because that is
    the earliest point the evidence exists. A FOR over a LOCAL reserves two
    temp words that are NOT declared LOCALs (q_locidx), but a literal bound
    leaves no op referring to either, so they cannot be found by anchoring --
    only by position. Position from the wrong end is what used to break: the
    FOR paths guessed `loop_var + 2` / `+ 4` and deleted whatever sat there
    mid-walk, which is a REAL declared LOCAL whenever the loop var is not the
    last one declared -- `LOCAL I%, S$` with `FOR I% = ...` puts S$'s
    descriptor exactly at `I% + 2` (t1_locstrafterfor / t1_locstrafterforlit;
    wild tbd73.exe's TBWINDOW `SUB Makevmenu`, `LOCAL done, mloop, ans$,
    ans1$`).

    The compiler allocates the temps at the frame TAIL, after every declared
    LOCAL, and reuses ONE pair however many LOCAL FORs the procedure contains
    (Makevmenu: 8 zero-filled words = 6 declared + 1 shared pair, across
    several FORs). So walk back from the tail -- and retire a word only if the
    body never touched it, which is the part a single forward pass cannot know
    at the FOR header. An untouched tail word is genuinely a temp; a touched
    one is a declared LOCAL that merely sits where a temp could.

    Deliberately NOT the unconditional `hidden_locals` path, which serves
    offsets the op stream DOES anchor -- the variable-limit case's limit-temp
    is reloaded by movax_bp at every test, so it is always touched and must be
    retired regardless.
    """
    if locs is None or not frame.has_local_for:
        return
    span = frame.local_span
    if span is None:
        return
    disp, cnt = span
    touched = frame.touched
    hidden = frame.hidden_locals
    for i in range(cnt - 1, -1, -1):  # tail-first; stop at the first word the
        d = disp + 2 * i  # body actually used -- everything below it is
        if d in hidden or d not in locs:
            # An anchored temp (the variable-limit case's limit-temp, retired
            # unconditionally just below -- it IS touched, since movax_bp
            # reloads it at every test, so it must not halt the walk), or the
            # high word of a string/SINGLE descriptor already folded into its
            # low word. Neither is evidence of a declared LOCAL here.
            continue
        if d in touched:  # a real declared LOCAL: no temp can be below it
            break
        locs.pop(d, None)


def _respell_params(node, spell, stmt_addr=None):
    """Rewrite `ir.Var("Pxx")` placeholders to the declared param spelling.

    Respelling REPLACES the statement object, so any `stmt_addr` entry keyed on
    the old `id()` would be orphaned and a jump target landing on that
    statement would no longer resolve -- the same identity hazard
    `_resolve_calls` documents, except here the node genuinely changes, so the
    address has to be MOVED rather than the rebuild avoided. Carried at every
    depth, since only the top-level walk knows which objects are statements.

    Witnessed by wild tbd73.exe: `SUB Makevmenu` forwards its by-ref array
    param `item$()` to `SUB Sprint INLINE`, so its whole body is respelled --
    including the `WHILE MID$(liveitem$,curntpos,1) <> "1"` header, which is
    the merge target of the preceding single-line nested IF/ELSE
    (`jump target 0xb192 is not a statement start`). Fixture t1_inlfwdwhile.
    """
    if isinstance(node, ir.Var) and node.name in spell:
        return ir.Var(spell[node.name])
    array_key = f"{node.name}(1)" if isinstance(node, ir.ArrayRef) else None
    if array_key in spell:
        return ir.ArrayRef(
            spell[array_key][:-3],
            tuple(_respell_params(i, spell, stmt_addr) for i in node.indices),
        )
    if isinstance(node, tuple):
        new = tuple(_respell_params(x, spell, stmt_addr) for x in node)
        return node if all(a is b for a, b in zip(node, new)) else new
    if not is_dataclass(node):
        return node
    changes = {}
    for f in fields(node):
        old = getattr(node, f.name)
        if isinstance(old, tuple):
            new = tuple(_respell_params(x, spell, stmt_addr) for x in old)
        else:
            new = _respell_params(old, spell, stmt_addr)
        if new is not old:
            changes[f.name] = new
    if not changes:
        return node
    new_node = replace(node, **changes)
    if stmt_addr is not None:
        a = stmt_addr.pop(id(node), None)
        if a is not None:
            stmt_addr.claim(new_node, a)
    return new_node


def _resolve_calls(
    stmts,
    proc_names,
    proc_params,
    inline_procs,
    proc_int_offs,
    proc_long_offs,
    proc_dbl_offs,
    proc_str_offs,
    stmt_addr=None,
):
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
                if target in inline_procs:
                    # A later-defined INLINE SUB has no parameter signature
                    # to resolve this deferred forwarded argument from.
                    new_args[i] = ir.Var(f"P{off:02X}")
                    changed = True
                    continue
                sfx = params[_idx][-1] if params[_idx][-1] in "%$&#" else ""
                if sfx == "%":
                    proc_int_offs.add(off)
                elif sfx == "$":
                    proc_str_offs.add(off)
                elif sfx == "&":
                    proc_long_offs.add(off)
                elif sfx == "#":
                    proc_dbl_offs.add(off)
                new_args[i] = ir.Var(f"P{off:02X}{sfx}")
                changed = True
            elif isinstance(a, tuple) and a and a[0] == "argrefpending":
                # Caller-side scalar forwarded by address to a callee defined
                # LATER in the file (handlers.control.calls's own "argref"
                # deferral, for a callee known at scan time -- this is the
                # forward-reference sibling): same type source, but this is
                # an ordinary DGROUP scalar (V#### -> canonical_rename),
                # not the callee's own PXX by-ref param.
                _, target, _idx, off, fallback = a
                params = proc_params[target]
                if target in inline_procs:
                    # Same no-signature case as fwdpending above: retain the
                    # caller's layout spelling captured at the call rather
                    # than indexing an empty INLINE parameter list (tbd73's
                    # Openbox call).
                    new_args[i] = fallback
                    changed = True
                    continue
                sfx = params[_idx][-1] if params[_idx][-1] in "%$&#" else ""
                new_args[i] = ir.Var(_slot(off) + sfx)
                changed = True
        return (tuple(new_args) if changed else args), changed

    def walk(body):
        new = [fix(s) for s in body]
        return body if all(a is b for a, b in zip(body, new)) else new

    def fix_value(v):
        if isinstance(v, ir.FnCall):
            new_args = tuple(fix_value(a) for a in v.args)
            name = v.name
            if isinstance(name, tuple) and name and name[0] == "addr":
                target = name[1]
                if target not in proc_names:
                    raise ValueError(f"unresolved forward FN target {target:#x}")
                name = proc_names[target]
            return (
                v
                if name == v.name and all(a is b for a, b in zip(v.args, new_args))
                else ir.FnCall(name, new_args)
            )
        if isinstance(v, tuple):
            new = tuple(fix_value(x) for x in v)
            return v if all(a is b for a, b in zip(v, new)) else new
        if is_dataclass(v):
            changes = {}
            for f in fields(v):
                old = getattr(v, f.name)
                new = fix_value(old)
                if new is not old:
                    changes[f.name] = new
            return v if not changes else replace(v, **changes)
        return v

    params_by_name = {
        proc_names[a]: proc_params[a] for a in proc_names if a in proc_params
    }

    def _check_relayed_arrays(name, args):
        """A relayed whole-array parameter (handlers.control's
        arg_push_array_bp) carries no element-type evidence: the SUB doing the
        relay never touches an element. Its unsuffixed P-name is only correct
        when the callee's own parameter is untyped too -- otherwise the header
        we would emit contradicts the callee's and TB rejects the source
        outright (probe probe_arrfwd, whose emitted form fails to recompile).
        Take the type from the callee here, the way `fwd` does for scalars,
        rather than emit something that cannot compile."""
        params = params_by_name.get(name)
        if params is None:
            return
        for i, a in enumerate(args):
            if not (
                isinstance(a, ir.ArrayRef)
                and not a.indices
                and a.name.startswith("P")
                and i < len(params)
            ):
                continue
            want = params[i][: params[i].index("(")] if "(" in params[i] else params[i]
            if want[-1:] in "%$&#" and not a.name.endswith(want[-1]):
                raise ValueError(
                    f"relayed array parameter {a.name} has no element-type "
                    f"evidence but callee {name} declares {params[i]}"
                )

    def fix(s):
        # Preserving the `is` identity of unchanged statements (see above) is
        # only half of it: a statement this pass DOES rebuild carries its
        # `stmt_addr` entry on the OLD object's id, so without moving it the
        # address is orphaned exactly as if the statement had been folded away
        # -- and a jump landing on it can never resolve. Bites the resolved
        # forward CALL itself: a SUB body whose CALL to a later-defined SUB is
        # a jump target (probe t1_fwdcalltgt; wild rsltest.exe's TBWINDOW
        # SUB1, an `IF c THEN <line>` skipping to a line that CALLs SUB4).
        new = _fix(s)
        if stmt_addr is not None and new is not s:
            a = stmt_addr.pop(id(s), None)
            if a is not None:
                stmt_addr.claim(new, a)
        return new

    def _fix(s):
        if isinstance(s, ir.CallStmt):
            new_args, args_changed = fix_args(s.args)
            if isinstance(s.name, tuple):
                target = s.name[1]
                if target in proc_names:
                    _check_relayed_arrays(proc_names[target], new_args)
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
            _check_relayed_arrays(
                proc_names[s.name[1]] if isinstance(s.name, tuple) else s.name,
                new_args,
            )
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
        return fix_value(s)

    resolved = walk(stmts)
    return _propagate_call_types(resolved, stmt_addr)


def _propagate_call_types(stmts, stmt_addr=None):
    """Refine unsuffixed SubDef parameter placeholders ('Pxx') using caller
    argument type evidence from CallStmts across the program (e.g., a parameter
    forwarded solely to a signature-less INLINE sub, where the callee provides no
    signature evidence, but the call site passes a typed argument like `W$`).
    """
    sub_defs: dict[str, ir.SubDef] = {}
    calls: list[tuple[str | None, ir.CallStmt]] = []

    def collect(body, owner=None):
        for s in body:
            if isinstance(s, ir.SubDef):
                sub_defs[s.name] = s
                collect(s.body, s.name)
            elif isinstance(s, ir.CallStmt):
                calls.append((owner, s))
            elif isinstance(s, ir.IfInline):
                collect(s.body, owner)
            elif isinstance(s, ir.IfBlock):
                for _, b in s.arms:
                    collect(b, owner)
                if s.else_body:
                    collect(s.else_body, owner)
            elif isinstance(s, ir.SelectCase):
                for arm in s.arms:
                    collect(arm.body, owner)
                if s.case_else:
                    collect(s.case_else, owner)
            elif isinstance(s, ir.DefFn) and s.is_block:
                collect(s.body, owner)

    collect(stmts)

    if not sub_defs or not calls:
        return stmts

    refinements: dict[str, dict[str, str]] = {}

    for owner, c in calls:
        if not isinstance(c.name, str) or c.name not in sub_defs:
            continue
        sub = sub_defs[c.name]
        for i, arg in enumerate(c.args):
            if i >= len(sub.params):
                continue
            p = sub.params[i]
            if p.startswith("P") and not p.endswith("(1)"):
                base = p.rstrip("%$&#")
                sfx = None
                # A caller's numeric type does not determine a by-ref formal's
                # spelling: TB accepts an INTEGER actual for an unsuffixed
                # (SINGLE) parameter, so propagating `%`, `&`, or `#` here
                # silently changes valid declarations.  Strings cannot undergo
                # that numeric coercion, making `$` the only calibrated
                # caller-side refinement (tbd73's Titlewin -> Titlebox INLINE).
                if isinstance(arg, ir.Var) and arg.name[-1:] == "$":
                    sfx = arg.name[-1:]
                elif isinstance(arg, ir.ArrayRef) and arg.name[-1:] == "$":
                    sfx = arg.name[-1:]
                elif isinstance(arg, ir.StrLit):
                    sfx = "$"
                if sfx:
                    want = f"{base}{sfx}"
                    if want != p:
                        refinements.setdefault(c.name, {})[p] = want

            # Passing an array element by reference proves the element type
            # when the receiving formal is already known.  The source array
            # descriptor itself is typed in its owner SUB's header, so update
            # that declaration (and its body references) rather than trying
            # to infer a type from the descriptor push.  This is the direct
            # `Drawlist(ptrarray$(...)) -> Printwin(..., strdat$)` chain in
            # tbd73; only `$` is safe for the same coercion reason above.
            if (
                owner in sub_defs
                and p[-1:] == "$"
                and isinstance(arg, ir.ArrayRef)
                and arg.name.startswith("P")
                and arg.name[-1:] != "$"
            ):
                owner_sub = sub_defs[owner]
                array_p = next(
                    (q for q in owner_sub.params if q == f"{arg.name}(1)"),
                    None,
                )
                if array_p is not None:
                    want = f"{arg.name}$(1)"
                    if want != array_p:
                        refinements.setdefault(owner, {})[array_p] = want

            # A whole-array relay carries the same descriptor type through
            # another SUB boundary.  The callee's `$(1)` formal is direct
            # evidence for the caller's matching array formal; unlike a
            # scalar numeric actual, this is not a coercion.  tbd73's
            # Makelmenu -> Drawlist relay is the witnessed shape.
            if (
                owner in sub_defs
                and p.endswith("$(1)")
                and isinstance(arg, ir.ArrayRef)
                and not arg.indices
                and arg.name.startswith("P")
                and arg.name[-1:] != "$"
            ):
                owner_sub = sub_defs[owner]
                array_p = next(
                    (q for q in owner_sub.params if q == f"{arg.name}(1)"),
                    None,
                )
                if array_p is not None:
                    want = f"{arg.name}$(1)"
                    if want != array_p:
                        refinements.setdefault(owner, {})[array_p] = want

    if not refinements:
        return stmts

    def update_stmt(s):
        if isinstance(s, ir.SubDef) and s.name in refinements:
            spell = refinements[s.name]
            new_params = tuple(spell.get(p, p) for p in s.params)
            new_body = tuple(_respell_params(b, spell, stmt_addr) for b in s.body)
            new_body = tuple(update_stmt(b) for b in new_body)
            return ir.SubDef(s.name, new_params, new_body)
        if isinstance(s, ir.SubDef):
            new_body = tuple(update_stmt(b) for b in s.body)
            return s if all(a is b for a, b in zip(s.body, new_body)) else ir.SubDef(s.name, s.params, new_body)
        if isinstance(s, ir.IfInline):
            new_body = tuple(update_stmt(b) for b in s.body)
            return s if all(a is b for a, b in zip(s.body, new_body)) else ir.IfInline(s.cond, new_body)
        if isinstance(s, ir.IfBlock):
            changed = False
            arms = []
            for cond, b in s.arms:
                nb = tuple(update_stmt(x) for x in b)
                changed = changed or any(x is not y for x, y in zip(b, nb))
                arms.append((cond, nb))
            eb = s.else_body
            if eb:
                neb = tuple(update_stmt(x) for x in eb)
                if any(x is not y for x, y in zip(eb, neb)):
                    changed = True
                    eb = neb
            return s if not changed else ir.IfBlock(tuple(arms), eb)
        if isinstance(s, ir.SelectCase):
            changed = False
            arms = []
            for arm in s.arms:
                nb = tuple(update_stmt(x) for x in arm.body)
                changed = changed or any(x is not y for x, y in zip(arm.body, nb))
                arms.append(ir.CaseArm(arm.guards, nb))
            ce = s.case_else
            if ce:
                nce = tuple(update_stmt(x) for x in ce)
                if any(x is not y for x, y in zip(ce, nce)):
                    changed = True
                    ce = nce
            return s if not changed else ir.SelectCase(s.selector, tuple(arms), ce)
        return s

    updated = [update_stmt(s) for s in stmts]
    # One refinement can expose the typed callee required by its caller (a
    # string literal fixes Printwin, then its array-element caller fixes
    # Drawlist).  Refinements only add a suffix, so this reaches a fixed point.
    return _propagate_call_types(updated, stmt_addr)



def _finalize(state: DecodeState, addr) -> Program:
    """Program epilogue: static-DIM re-emit, control-flow folds, target
    resolution and canonical rename -> the finished Program."""
    # Whatever regions are still queued belong to the main program, whose
    # close is here: the walk is over and nothing else will snapshot them.
    state.drain_folds()
    with editing(state.output.stmts, "finalize"):
        img, lyt, c, out = (state.image, state.layout_state,
                            state.control, state.output)
        out.stmts[:] = _resolve_calls(
            out.stmts,
            c.proc_names,
            c.proc_params,
            c.inline_procs,
            c.proc_int_offs,
            c.proc_long_offs,
            c.proc_dbl_offs,
            c.proc_str_offs,
            out.stmt_addr,
        )
        # Error-trap line table, probed early -- before DATA/dims/COMMON/TRON
        # synthesis below mutates out.addrs -- so a codeless DATA statement
        # with no READ/RESTORE anywhere to trigger its recovery (wild
        # vhfprop.exe) can still be found from its ORPHAN table entry (see
        # `_line_table`'s docstring). out.stmt_addr is already fully
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
            for o in img.ops
        ):
            _early = _line_table(
                img.exe,
                img.start,
                out.addrs,
                addr,
                extra_offs={a + 4 - img.start for a in out.trace_tbl}
                | {a - img.start for a in out.stmt_addr.values() if a is not None},
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
        # loop's own runtime `c.dos` nesting would).
        if table_active:
            # Every Do (bare or head-test) is pushed, so a head-test DO's own
            # closing (bare) Loop pops ITS Do and not some enclosing bare one --
            # only a BARE Do's pairing is recorded for possible conversion.
            do_stack: list[tuple[int, bool]] = []
            do_to_loop: dict[int, int] = {}
            for i, s in enumerate(out.stmts):
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
                if out.addrs[do_idx] is not None:
                    continue  # a real (non-synthesized) Do -- untouched
                host = out.addrs[do_idx + 1]
                if host is None:
                    continue
                host_off = host - img.start
                if host_off in orphan_offs:
                    claimed_offs.add(host_off)  # a genuine DO -- not DATA/DIM's to see
                    do_idx_lines[do_idx] = off_to_line[host_off]
                    continue
                loop_s = out.stmts[loop_idx]
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
                    out.stmts[loop_idx] = ir.IfGoto(loop_s.cond, ("addr", host))
                    drop.add(do_idx)
                    continue
                out.stmts[loop_idx] = ir.Goto(("addr", host))
                drop.add(do_idx)
            if drop:
                keep = [i for i in range(len(out.stmts)) if i not in drop]
                out.stmts[:] = [out.stmts[i] for i in keep]
                out.addrs[:] = [out.addrs[i] for i in keep]
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
        ob = lyt.option_base if lyt.option_base is not None else 0
        dims, local_dims, cur_ob = [], {}, 0  # BASIC default at program top
        for a in reversed(lyt.arrs):
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
                # A SUB-local static array: its DIM belongs inside that body, and
                # allocation order is preserved by emit0 keeping each SUB at its
                # ORIGINAL position rather than hoisting it, so the recovered DIM
                # lands on the same side of the main DIMs it started on. Static
                # array data allocates DESCENDING in DIM order (first DIM = highest
                # base; `lyt.arrs` is ascending by base, hence the reversed walk),
                # and BOTH directions are now witnessed byte-exact:
                #
                #   t1_subad        SUB emitted FIRST  -> its array has the HIGHEST
                #                                        base (0x1e0 vs main 0x1b0)
                #   t1_sublocafter  SUB emitted AFTER  -> its array has the LOWEST
                #                                        base (0x1f0 vs main 0x2c0,
                #                                        0x2f0); wild tbd73.exe's
                #                                        `SUB Showfile` is this
                #                                        shape, and prtguide.exe too
                #
                # A guard used to sit here rejecting the second case (`if dims:
                # raise`, reached in a descending walk exactly when the SUB-local
                # array is the lowest-based one). It was a conservative guess -- its
                # own message said "no witness" -- and it was backwards. Replacing
                # it with the opposite inequality is equally wrong: that rejects
                # t1_subad, which has always round-tripped byte-exact. There is no
                # single direction to assert, because the answer depends on where
                # the SUB sits, which emit0 already reproduces; so nothing is
                # asserted here beyond the OPTION BASE invariant below.
                if want != cur_ob:
                    raise ValueError(
                        "OPTION BASE change around a SUB-local array (no witness)"
                    )
                local_dims.setdefault(sub_local_arrays[a["name"]], []).append(
                    ir.Dim(a["name"], bounds)
                )
                continue
            if want != cur_ob:
                dims.append(ir.OptionBase(want))
                cur_ob = want
            dims.append(ir.Dim(a["name"], bounds))
        if lyt.option_base == 1 and cur_ob != 1:  # runtime DIMs witness OB1
            dims.append(ir.OptionBase(1))  # (lo-store order)
        # Rebuild SUB bodies: SHARED declaration first, then local static DIMs,
        # then the decoded body (canonical order; verified byte-exact against the
        # t1_subsh/t1_subarr/t1_subad witnesses).
        for i, s in enumerate(out.stmts):
            if not isinstance(s, ir.SubDef):
                continue
            prefix = []
            if i in shared_subs:
                shared = shared_subs[i]
                # Turbo Basic accepts only ten SHARED names in one source
                # statement.  Keep the groups as actual body statements, rather
                # than splitting them in emit0 after BodyLine targets have already
                # been assigned: tbd73's Initmenus has forty names and branches
                # immediately after the declarations.
                prefix.extend(
                    ir.Shared(tuple(shared.names[j : j + 10]))
                    for j in range(0, len(shared.names), 10)
                )
            prefix.extend(local_dims.get(i, ()))
            if prefix:
                out.stmts[i] = ir.SubDef(s.name, s.params, tuple(prefix) + s.body)
        ins = 0  # static DIMs follow any proc definitions
        while ins < len(out.stmts) and isinstance(
            out.stmts[ins], (ir.SubDef, ir.DefFn)
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
                ins = out.addrs.index(img.start + next(iter(offs)))
                dim_lines = [ln for _, ln in data_orphan_lines]
                data_orphan_lines = []  # consumed -- DATA recovery below won't fire
        for offset, declaration in enumerate(dims):
            state.reconstruct(ins + offset, declaration)
        if dims:
            # `$SEGMENT` positions are recorded while scanning executable code;
            # recovered static DIMs are codeless and inserted afterwards.  Rebase
            # every following meta index so the directive remains before the same
            # scanned statement (tbd73's four leading DIMs).
            out.seg_metas = [
                i + len(dims) if i >= ins else i for i in out.seg_metas
            ]
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
        if any(isinstance(s, (ir.Read, ir.Restore)) for s in out.stmts) or data_orphan_lines:
            items = lyt.data_items or _read_data_pool(img.exe)
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
                    j = out.addrs.index(img.start + off)
                    state.reconstruct(j, ir.DefType())
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
                        for s in out.stmts
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
                        for s in out.stmts
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
                        j = out.addrs.index(img.start + off)
                        state.reconstruct(j, s)
                else:
                    for offset, s in enumerate(data_block):
                        state.reconstruct(offset, s)  # prepend: block pos = final index
                # Insert payload-free codeless declarations after DATA placement;
                # when both borrow the same host offset this preserves table order.
                for off, ln in deftype_places:
                    j = out.addrs.index(img.start + off)
                    state.reconstruct(j, ir.DefType())
                    deftype_lines.append(ln)
                out.stmts[:] = [
                    (
                        ir.Restore(item_to_stmt[s.target])
                        if isinstance(s, ir.Restore) and isinstance(s.target, int)
                        else s
                    )
                    for s in out.stmts
                ]
        # EXIT FOR/LOOP folds (Task 3.1): rewrite the early-exit GOTO to the loop
        # exit, then fold `IF c THEN <skip>` + EXIT into `IF negate(c) THEN EXIT`.
        _apply_exit_folds(out.stmts, out.addrs, c.exit_folds)
        out.stmts[:], out.addrs[:] = _fold_if(
            out.stmts,
            out.addrs,
            targets=_jump_targets(out.stmts),
            stmt_addr=out.stmt_addr,
            block_ifs=c.block_if_addrs,
        )  # multi-line IF blocks (Task 3.3)
        fixed_lines = None
        trace_partial: dict[int, int] = {}
        _top_addrs = {a for a in out.addrs if a is not None}
        orphans = {a: l for a, l in out.trace_tbl.items() if a not in _top_addrs}
        traced_idx: set[int] = set()
        # A fully-traced block's inner-body hooks are also "orphans" (folded away),
        # but the normal path consumes them via hook_seq physical-line counting.
        # The mid-body-TROFF signature is narrower: the REGION-END hook itself (the
        # last, highest-address hook) stamps a body statement rather than a
        # top-level statement start (t1_troffin) -- there is no post-block TROFF.
        if out.trace_tbl and orphans and max(out.trace_tbl) not in _top_addrs:
            # Region ends INSIDE a block body: the TROFF hook stamps a body
            # statement, so it never surfaces as a top-level addr (t1_troffin).
            out.stmts[:], out.addrs[:], fixed_lines, trace_partial = (
                _lift_midblock_troff(
                    out.stmts,
                    out.addrs,
                    out.trace_tbl,
                    orphans,
                    out.stmt_addr,
                    out.hook_seq,
                )
            )
            traced_idx = set(trace_partial)  # the block; floor pins are not traced
        elif out.trace_tbl:
            # TRON/TROFF lift: each hook paired with the statement that kept cur
            # on it. TRON/TROFF themselves compile to no code, so both are
            # synthesized per contiguous hook run (t1_tron2r2 has two): TRON
            # before the run's first statement, and -- because TROFF's own line
            # still carries a hook -- when unhooked statements follow the run,
            # its LAST hook is TROFF's and the statement paired with it is
            # really the first post-region statement (witnessed t1_tron2). A run
            # reaching program end keeps the hook line on its last statement
            # (TROFF-before-END is byte-invisible, t1_tron_troff).
            hooked = [i for i, a in enumerate(out.addrs) if a in out.trace_tbl]
            if not hooked:
                raise ValueError("trace hooks present but paired with no statement")
            runs: list[Any] = []
            for i in hooked:
                if runs and i == runs[-1][-1] + 1:
                    runs[-1].append(i)
                else:
                    runs.append([i])
            hookline = {i: out.trace_tbl[out.addrs[i]] for i in hooked}
            starts = {r[0] for r in runs}
            demote = {r[-1] for r in runs if r[-1] < len(out.stmts) - 1}
            new_s, new_a, fixed_lines = [], [], {}
            for i, (s, a) in enumerate(zip(out.stmts, out.addrs)):
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
            out.stmts[:], out.addrs[:] = new_s, new_a
            traced_idx = set(fixed_lines)
        # COMMON compiles to no ops -- only the DGROUP band stamps the layout
        # solver recovered (see layout._bands_layout). Synthesize the canonical
        # declaration as the first statement, named/typed via loc() like any
        # other slot (witnessed t1_common1).
        # A COMMON'd ARRAY leaves no scalar slot at all -- its 0x36 descriptor block
        # simply sits in the band instead of the ordinary grid -- so its declaration
        # is recovered from the block position and spelled with its rank, the way
        # TB requires (`COMMON A(1)`, probe t1_commonarr; wild tbd73.exe).
        common_arrs = [
            lyt.r_arrs[b]["name"] + f"({img.exe[lyt.ds + b + 3]})"
            for b in lyt.lay.get("common_arrs", ())
            if b in lyt.r_arrs
        ]
        if lyt.lay.get("common_slots") or common_arrs:
            if fixed_lines is not None:
                raise ValueError("COMMON alongside TRON trace hooks is unsupported")
            names = tuple(common_arrs) + tuple(
                state.loc(d).name for d in lyt.lay.get("common_slots") or ()
            )
            # Scalar COMMON goes first (t1_common1), but a COMMON'd array has to be
            # DIMmed before it is named -- TB compiles the two orders two bytes
            # apart, and only DIM-then-COMMON reproduces the input.
            at = 0
            if common_arrs:
                while at < len(out.stmts) and isinstance(out.stmts[at], ir.Dim):
                    at += 1
            state.reconstruct(at, ir.Common(names))
            out.seg_metas = [i + 1 if i >= at else i for i in out.seg_metas]
        # $EVENT regions: when trapping is in play the compiler emits a CC
        # poll hook before EVERY statement; $EVENT OFF..ON suppresses them
        # for a run of statements (witnessed t1_evreg), or everywhere when OFF
        # precedes all statements (t1_evoff -- RETURN stays CB either way).
        # Synthesize a pragma line at each hooked/unhooked transition.
        ev_metas = []
        if out.cc_hooks or any(o[1] in ("on_trap", "trap_ctl") for o in img.ops):
            on = True  # compiler default: $EVENT ON
            for i, a in enumerate(out.addrs):
                if a is None:  # synthesized stmt: state persists
                    continue
                if (a in out.cc_hooks) != on:
                    on = not on
                    ev_metas.append((i, f"$EVENT {'ON' if on else 'OFF'}"))
        if lyt.discard_strs:
            raise ValueError(
                "pooled string literals left unattached after the "
                "fre_str sites were served (unsupported shape)"
            )
        graph = ControlGraph.from_statements(out.stmts, out.addrs, out.stmt_addr)
        graph.validate_targets()
        # Reconcile against the folded-but-not-yet-canonical statements: this is
        # the boundary where folding is done and renaming has not started, so a
        # difference here is a fold and nothing else. Comparing against the final
        # program would report every renamed variable as a lost statement.
        if isinstance(out.stmts, RecordedStatements):
            # Losslessness gate. An edit that bypassed the recorder shows up here
            # as a divergence, at the point the list is final and before anything
            # renames it.
            rebuilt = replay(out.stmts.edits)
            if rebuilt != list(out.stmts):
                raise ValueError(
                    "statement edit log does not rebuild the statement list "
                    f"({len(rebuilt)} replayed vs {len(out.stmts)} final)"
                )
        events = state.events
        reconciliation = reconcile(events, out.stmts)
        canonical = canonical_rename(
            _resolve_targets(out.stmts, out.addrs, out.stmt_addr)
        )
        prog = Program(canonical)
        prog.control_graph = graph
        # The event log is what the decoder committed, addresses unresolved, before
        # control-flow folding rewrote the statement list. It runs alongside the
        # existing path rather than feeding it: `event_reconciliation` measures how
        # far the two have diverged, which is the input the control-flow extraction
        # needs before replay can become authoritative.
        prog.events = events
        prog.event_reconciliation = reconciliation
        prog.statement_edits = (
            tuple(out.stmts.edits)
            if isinstance(out.stmts, RecordedStatements)
            else ()
        )
        prog.fold_regions = tuple(c.fold_plan or ())
        prog.metas = (
            tuple((0, m) for m in out.metas)
            + tuple((i, "$SEGMENT") for i in out.seg_metas)
            + tuple(ev_metas)
        )
        prog.toggles = out.toggles
        if fixed_lines is not None:
            prog.lines = _fill_lines(fixed_lines, len(prog))
            # emit0 numbers one physical line per hook inside traced
            # statements (block bodies in a TRON region carry their own
            # hooks -- t1_tronif/t1_troncase)
            prog.hook_seq = tuple(out.hook_seq)
            prog.traced = tuple(sorted(traced_idx))
            # A block whose region ends mid-body traces only a prefix of its
            # physical lines (t1_troffin): {stmt index -> traced line count}.
            prog.trace_partial = dict(trace_partial)
        if any(
            o[1] in ("resume_pre", "on_error", "error_stmt")
            or (o[1] == "movax_m" and o[2] in (0x72, 0x74))
            for o in img.ops
        ):
            _late = _line_table(
                img.exe,
                img.start,
                out.addrs,
                addr,
                extra_offs={a + 4 - img.start for a in out.trace_tbl}
                | {
                    a - img.start
                    for a in out.stmt_addr.values()
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
                for i, a in enumerate(out.addrs):
                    if a is None:
                        continue
                    off = a - img.start
                    line = table.get(off, table.get(off + 4))
                    if line is None:
                        raise ValueError(
                            "TRON-region statement missing from the error-trap "
                            "line table (unsupported shape)"
                        )
                    real[i] = line
                real.update(
                    {i: ln for i, ln in fixed_lines.items() if out.addrs[i] is None}
                )  # the demoted-TROFF pairing
                prog.lines = _fill_lines(real, len(prog))
            elif table is not None:
                try:
                    pending_data_lines = iter(data_lines or ())
                    pending_dim_lines = iter(dim_lines or ())
                    pending_do_lines = iter(do_lines or ())
                    pending_deftype_lines = iter(deftype_lines)
                    lines = []
                    for s, a in zip(prog, out.addrs):
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
                            lines.append(table[a - img.start])
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
    img, m, e, l, c, out = (state.image, state.machine, state.expr,
                            state.layout_state, state.control, state.output)
    if kind == "fld1":
        e.stack.append(ir.Lit(1))
    elif kind == "fldz":
        e.stack.append(ir.Lit(0))
    elif kind == "fild":
        if op[2] == 0x2C:
            raise ValueError(f"FILD [002C] without a bridge at {addr:#x}")
        if op[2] == 0x74:  # runtime cells, not user slots (FP-context
            e.stack.append(ir.Err())  # read, e.g. PRINT ERR --
        elif op[2] == 0x72:  # witnessed t1_suberr)
            e.stack.append(ir.Erl())
        elif op[2] in l.lay["scalars"]:
            e.stack.append(state.loc(op[2]))  # integer variable read
        else:
            e.stack.append(state.pool_lit(op[2]))
    elif kind == "fld":
        e.stack.append(state.fpval(op[2]))
    elif kind == "fld64":  # m64 load: double var or pooled f64
        e.stack.append(state.fpval64(op[2]))
    elif kind == "fstp64":  # m64 store: double var assign
        v = e.stack.pop()
        if v is _FREAD:
            state._fread_target(state.loc(op[2]))
        elif v is _READDATA:
            state._readdata_target(state.loc(op[2]))
        elif op[2] < VAR_BASE and op[2] not in l.lay["scalars"]:
            # Transient promote-once/compare-many scratch cell (see
            # m.fp64_bridge's own comment) -- invisible in the source,
            # not a real variable.
            m.fp64_bridge[op[2]] = v
        else:
            state.put(ir.Assign(state.loc(op[2]), v), c.cur)
        c.cur = None
    elif kind == "fold64":  # m64 arithmetic, mem LEFT
        e.stack.append(_orient(op[2], state.fpval64(op[3]), e.stack.pop()))
    elif kind == "fold_n64":  # m64 non-R: mem RIGHT
        top = e.stack.pop()
        if isinstance(top, ir.BinOp) and _PREC[top.op] < _PREC[op[2]]:
            top = ir.Group(top)
        e.stack.append(ir.BinOp(op[2], top, state.fpval64(op[3])))
    elif kind == "fild32":  # m32 int load: long var or pooled i32
        if op[2] == 0x6E:  # runtime dword cell [006E]: ERADR
            e.stack.append(ir.Nullary("ERADR"))
        else:
            try:
                e.stack.append(state.loc(op[2]))
            except ValueError:
                e.stack.append(state.pool_lit32(op[2]))
    elif kind == "fistp32":  # m32 int store: long var assign
        v = e.stack.pop()
        if v is _FREAD:
            state._fread_target(state.loc(op[2]))
        elif v is _READDATA:
            state._readdata_target(state.loc(op[2]))
        else:
            state.put(ir.Assign(state.loc(op[2]), v), c.cur)
        c.cur = None
    elif kind == "ifold32":  # m32 long arithmetic, mem LEFT
        try:
            mem = state.loc(op[3])
        except ValueError:
            mem = state.pool_lit32(op[3])
        e.stack.append(_orient(op[2], mem, e.stack.pop()))
    elif kind == "frndint":  # FRNDINT = CLNG intrinsic
        e.stack.append(ir.Call("CLNG", (e.stack.pop(),)))
    elif kind == "strfn":  # string-result intrinsic
        name = op[2]
        if name in ("CHR$", "SPACE$", "MKI$", "INPUT$", "IOCTL$"):  # integer arg in ax
            args = (m.ax,)
            m.ax = None
        elif name == "INPUT$F":  # INPUT$(n, f): n in bx (shuttled), f in ax
            name = "INPUT$"
            f = m.ax
            m.ax = None
            n = m.bx
            m.bx = None
            args = (n, f)
        elif name == "STRING$S":  # STRING$(n, s$): n in ax, s$ on sstack
            name = "STRING$"
            n = m.ax
            m.ax = None
            args = (n, e.sstack.pop())
        elif name == "MID$2":  # MID$(s$, start): s$ on sstack, start in ax
            name = "MID$"
            n = m.ax
            m.ax = None
            args = (e.sstack.pop(), n)
        elif name in ("LEFT$", "RIGHT$"):  # string on sstack, count in ax
            n = m.ax
            m.ax = None
            args = (e.sstack.pop(), n)
        elif name == "MID$":  # s$ on sstack, start in bx, len in ax
            ln = m.ax
            m.ax = None
            st = m.bx
            m.bx = None
            args = (e.sstack.pop(), st, ln)
        elif name == "STRING$":  # n in bx (shuttled), ch in ax
            ch = m.ax
            m.ax = None
            n = m.bx
            m.bx = None
            args = (n, ch)
        elif name in (
            "INKEY$",
            "DATE$",
            "TIME$",
            "COMMAND$",
            "ERDEV$",
        ):  # zero-arg: bare keyword
            e.sstack.append(ir.Nullary(name))
            state.advance()
            return
        elif name in ("UCASE$", "LCASE$", "ENVIRON$"):  # string arg via sstack
            args = (e.sstack.pop(),)
        else:  # STR$/HEX$/OCT$/BIN$/MKL$/MKS$/MKD$:
            args = (e.stack.pop(),)  # numeric arg via the FP stack
        e.sstack.append(ir.Call(name, args))
    elif kind == "str2num":  # string-arg numeric intrinsic
        if op[2] == "INSTR":
            sub = e.sstack.pop()  # needle pushed last
            hay = e.sstack.pop()
            call = ir.Call("INSTR", (hay, sub))
        else:
            call = ir.Call(op[2], (e.sstack.pop(),))
        if op[2] in ("VAL", "CVS", "CVD", "CVL"):
            e.stack.append(call)  # result on the FP stack
        else:
            m.ax = call  # ASC/LEN/INSTR/CVI: result in ax
    elif kind == "instr3":  # INSTR start in ax, strings pushed haystack first
        needle = e.sstack.pop()
        haystack = e.sstack.pop()
        m.ax = ir.Call("INSTR", (m.ax, haystack, needle))
    elif kind == "fchs":
        e.stack.append(ir.Neg(e.stack.pop()))
    elif kind == "fabs":
        e.stack.append(ir.Call("ABS", (e.stack.pop(),)))
    elif kind == "fsqrt":
        e.stack.append(ir.Call("SQR", (e.stack.pop(),)))
    elif kind == "fn":  # runtime intrinsic
        e.stack.append(ir.Call(op[2], (e.stack.pop(),)))
    elif kind == "fn_ax":  # ax-returning intrinsic
        m.ax = ir.Call(op[2], (e.stack.pop(),))
    elif kind == "fn_ax_ax":  # ax-arg ax-returning (REG(n))
        m.ax = ir.Call(op[2], (m.ax,))
    elif kind == "fn_ax0":  # zero-arg ax-returning; POS/PLAY
        m.ax = (
            ir.Call(op[2], (ir.Lit(0),))  # keep their required dummy args
            if op[2] in ("POS", "PLAY")
            else ir.Nullary(op[2])
        )
    elif kind == "fn_fp0":  # zero-arg FP-returning
        e.stack.append(ir.Nullary(op[2]))
    elif kind == "fn_axfp":  # ax-arg, FP-stack-returning (FRE(n))
        e.stack.append(ir.Call(op[2], (m.ax,)))
        m.ax = None
    elif kind == "fre_str":  # FRE(s$): the operand compiles to
        e.stack.append(
            ir.Call(
                "FRE",  # nothing -- variables render as
                (
                    (
                        l.discard_strs.pop(0)
                        if l.discard_strs  # FRE(""), pooled
                        else ir.StrLit("")
                    ),
                ),
            )
        )  # literals are re-attached here
    elif kind == "pmap":  # PMAP(x, n): x FP stack, n ax
        e.stack.append(ir.Call("PMAP", (e.stack.pop(), m.ax)))
        m.ax = None
    elif kind == "movaxds":  # mov ax,ds: VARSEG of a DGROUP var;
        m.ax = ir.VarSeg()  # rendered against the assign target
    elif kind == "fn_screen":  # SCREEN(row, col): bx, ax
        m.ax = ir.Call("SCREEN", (m.bx, m.ax))
        m.bx = None
    elif kind == "fn_screen_color":  # SCREEN(row, col, color): cx, bx, ax
        m.ax = ir.Call("SCREEN", (m.cx, m.bx, m.ax))
        m.cx = m.bx = None
    elif kind == "fn_ax2":  # two-FP-arg ax intrinsic (POINT)
        y = e.stack.pop()
        x = e.stack.pop()
        m.ax = ir.Call(op[2], (x, y))
    elif kind == "popop":
        last = e.stack.pop()  # last-pushed is the textual LEFT
        first = e.stack.pop()  # (R-form FSUBRP: st1=st0-st1, and
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
            e.stack.append(ir.BinOp(op[2], first, last))
        else:
            e.stack.append(ir.BinOp(op[2], _grp(last), _grp(first)))  # R-first
    elif kind == "popop_n":  # non-R: first-pushed is LEFT
        rhs = e.stack.pop()
        lhs = e.stack.pop()
        # lhs was built as a fold chain (no outer group) -- leaving it bare lets
        # TB evaluate it left-first and emit FDIVP/FSUBP.
        # Wrapping lhs in _grp would cause TB to reorder evaluation (right-first)
        # and emit the R-form FDIVRP/FSUBRP instead.
        e.stack.append(ir.BinOp(op[2], lhs, _grp(rhs)))
    elif kind == "fold":
        e.stack.append(_orient(op[2], state.fpval(op[3]), e.stack.pop()))
    elif kind == "fold_n":  # non-R: mem is the RIGHT operand
        top = e.stack.pop()
        if isinstance(top, ir.BinOp) and _PREC[top.op] < _PREC[op[2]]:
            top = ir.Group(top)  # (B + C) / D: parens required
        e.stack.append(ir.BinOp(op[2], top, state.fpval(op[3])))
    elif kind == "ifold_n":
        right = (
            state.loc(op[3]) if op[3] in l.lay["scalars"] else state.pool_lit(op[3])
        )
        top = e.stack.pop()
        if isinstance(top, ir.BinOp) and _PREC[top.op] < _PREC[op[2]]:
            top = ir.Group(top)
        e.stack.append(ir.BinOp(op[2], top, right))
    elif kind == "ifold":  # int var or pool literal
        mem = (
            state.loc(op[3]) if op[3] in l.lay["scalars"] else state.pool_lit(op[3])
        )
        e.stack.append(_orient(op[2], mem, e.stack.pop()))
    elif kind == "fstp" and op[2] in (0x88, 0x94, 0xA0, 0xAC):
        e.color_cells[op[2]] = e.stack.pop()  # WINDOW world-coord cell (FP leg)
    elif kind == "fstp":
        if e.stack:
            v = e.stack.pop()
        elif isinstance(m.ax, ir.Call):
            # An ax-arg/ax-returning intrinsic (LOC(n): `movax n; fn_ax_ax`)
            # feeding STRAIGHT into an FP-typed target with no explicit
            # fistp/movmem_ax/fild bridge at all -- the compiler promotes
            # ax to FP implicitly here rather than through the usual
            # int->FP round trip (wild be.exe/styllist.exe, probe q_loc1).
            v = m.ax
            m.ax = None
        else:
            raise ValueError(f"fstp with empty FP stack at {addr:#x}")
        # Implicit-single narrowing: a pooled f64 literal stored to a width-4
        # non-long slot was an unsuffixed source literal (`A = 1.5`) -- render
        # it plain (a `#` or `!` suffix would not be byte-faithful).
        if (
            isinstance(v, ir.DblLit)
            and l.lay["scalars"].get(op[2]) == 4
            and op[2] not in l.lay["long_slots"]
        ):
            v = ir.SingleLit(v.value)
        if v is _FREAD:  # INPUT# near numeric target
            state._fread_target(state.loc(op[2]))
        elif v is _READDATA:  # READ numeric target
            state._readdata_target(state.loc(op[2]))
        else:
            state.put(ir.Assign(state.loc(op[2]), v), c.cur)
        c.cur = None
    elif kind == "fcomp":
        e.pend_cmp = (state.fpval(op[2]), e.stack.pop())
    elif kind == "icomp":  # m16 int var/pool-literal compare (mixed-type
        # IF/loop test against an FP-stack value; wild grdscn.exe et al.)
        mem = (
            state.loc(op[2]) if op[2] in l.lay["scalars"] else state.pool_lit(op[2])
        )
        e.pend_cmp = (mem, e.stack.pop())
    elif kind == "icomp_bp":  # LOCAL int compare (mixed-type IF/loop test
        # against an FP-stack value; the bp-relative sibling of icomp, wild
        # bmaster.exe/ifi.exe)
        e.pend_cmp = (state.loc_local(op[2]), e.stack.pop())
    elif kind == "icomp32":  # m32 long-int var/pool-literal compare: the
        # LONG (`&`) sibling of icomp (`IF X& > 5.5 THEN`; wild stat.exe)
        mem = (
            state.loc(op[2])
            if op[2] in l.lay["scalars"]
            else state.pool_lit32(op[2])
        )
        e.pend_cmp = (mem, e.stack.pop())
    elif kind == "fcomp64":  # m64 direct compare outside SELECT CASE (which
        # consumes its own): double var or pooled f64 (witnessed t1_dblarr)
        e.pend_cmp = (state.fpval64(op[2]), e.stack.pop())
    elif kind == "fcompp":  # both sides FP-computed: LHS pushed first, so
        rhs = e.stack.pop()  # flags (ST0 cmp ST1 = rhs cmp lhs) keep the
        e.pend_cmp = (e.stack.pop(), rhs)  # reversed FP orientation
    elif kind == "strcmp":  # string relational IF (outside SELECT CASE, which
        rhs = e.sstack.pop()  # consumes its own strcmp ops): forward flags
        e.pend_cmp = (e.sstack.pop(), rhs)
        e.pend_cmp_str = True
    elif kind == "orax" and e.pend_cmp is None and m.ax is not None:
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
        nxt = img.ops[c.k + 1] if c.k + 1 < len(img.ops) else None
        if (
            nxt is not None
            and nxt[1] == "jcc"
            and nxt[2] in (0x74, 0x75)
            and nxt[3] < addr
            and nxt[3] in out.addrs
        ):
            loop_kind = "WHILE" if nxt[2] == 0x75 else "UNTIL"
            idx = out.addrs.index(nxt[3])
            with editing(out.stmts, "fold_loop_header"):
                out.stmts.insert(idx, ir.Do(None))
            out.addrs.insert(idx, None)
            state.shift_pending(idx, 1)
            state.put(ir.Loop(loop_kind, m.ax), c.cur)
            m.ax = None
            c.cur = None
            state.advance(2)
            return
        if (
            nxt is not None
            and nxt[1] == "jcc"
            and nxt[2] in (0x74, 0x75)
            and c.k + 2 < len(img.ops)
            and img.ops[c.k + 2][1] == "jmp"
            and nxt[3] == img.ops[c.k + 2][0] + 3
        ):
            test_addr = _find_jmps_back(img.ops, img.ops[c.k + 2][2])
            if test_addr is not None:
                # HEAD-test DO/WHILE loop whose condition is a bare value
                # with no materialization prefix -- the head-test sibling
                # of the tail-test case just above (same "byte-exact bare
                # form only" rule: a real comparison compiles the full
                # movax-FFFF/jcc/incax template instead, handled by
                # _lift_while). Structurally identical to _lift_while's own
                # head-test branch, just without a pend_cmp to materialize
                # first (wild rsltest.exe: `WHILE NOT INSTAT` / `WEND`, an
                # empty-body busy-wait poll under active event trapping).
                loop_kind = "WHILE" if nxt[2] == 0x75 else "UNTIL"
                state.put(ir.Do(loop_kind, m.ax), c.cur)
                state.branch(
                    "loop", template="poll_loop",
                    target=img.ops[c.k + 2][2], address=test_addr,
                )
                c.dos.append(
                    LoopFrame(test=test_addr, exit=img.ops[c.k + 2][2])
                )
                m.ax = None
                state.advance(3)
                return
            if match_bool_bare_term1(img.ops, c.k) is not None:
                # A bare-value (uncompared) compound-AND first term (wild
                # rsltest.exe: `PEEK(&H410) AND &H40 = 48`) -- stage it as
                # e.pend_bool exactly as match_bool_term1's caller
                # does for a comparison-based term1, so the ordinary
                # movax_family dispatch (control.py) folds term2's own
                # materialization into it once reached.
                e.pend_bool = BoolTerm(
                    r1=m.ax,
                    op="AND",
                    sc=img.ops[c.k + 2][2],
                    start=c.cur,
                )
                m.ax = None
                state.advance(3)
                return
            if nxt[2] == 0x75 and any(
                o[0] == img.ops[c.k + 2][2] - 2 and o[1] == "andaxbx"
                for o in img.ops
            ):
                # A bare value as the LEFT operand of an ungrouped outer AND
                # whose RIGHT operand is a parenthesized GROUP: `IF F% AND
                # (A$ = CHR$(75) OR A$ = CHR$(77))` (t1_boolstrgroup; wild
                # tbd73.exe's TBWINDOW `SUB Makevmenu`, `IF hmenuopen AND
                # (ans1$ = CHR$(75) OR ans1$ = CHR$(77))`).
                #
                # `or ax,ax` self-tests the value WITHOUT destroying it, so
                # unlike match_bool_bare_term1's flat-chain case just above
                # this must NOT clear ax: the very next `movbxax` banks it in
                # bx, the group is then computed in ax (parking bx in cx
                # meanwhile), and a final `andaxbx` folds the two. That whole
                # right-hand-group protocol is exactly what direct_bool_gate
                # already drives for t1_nestedbool -- whose left operand is a
                # folded group (`oraxbx`) rather than a bare value, and which
                # therefore enters through the jcc handler's `direct_bool`
                # test instead of here. So set the same flag and let the
                # existing machinery run: arith's andaxbx branch reads it to
                # put bx (this value) on the LEFT, and the jcc handler reads
                # it to skip the extra Group wrapper before clearing it.
                #
                # Distinguished from the flat AND-chain above by WHERE the
                # outer fold sits: a chain folds immediately after its second
                # term's materialization, a group only after its own inner
                # fold. Both agree the short-circuit lands two bytes past the
                # outer `andaxbx`, so that is the anchor tested here. AND only
                # (cc 75), matching match_bool_bare_term1's own restriction:
                # a bare-value OR term1 stays unwitnessed.
                e.direct_bool_gate = True
                state.advance(3)
                return
        e.pend_cmp = (m.ax, ir.Lit(0))
        m.ax = None
    elif kind == "fstsw":
        pass
    elif kind == "jcc":
        cc, t = op[2], op[3]
        nxt = img.ops[c.k + 1] if c.k + 1 < len(img.ops) else None
        prev = img.ops[c.k - 1] if c.k else None
        direct_bool = (
            e.pend_cmp is None
            and m.ax is not None
            and cc in (0x74, 0x75)
            and prev is not None
            and prev[1] in ("andaxbx", "oraxbx", "xoraxbx")
            and nxt is not None
            and nxt[1] in ("jmp", "jmpf")
            and t == nxt[0] + (5 if nxt[1] == "jmpf" else 3)
        )
        if cc == 0x75 and direct_bool and any(
            candidate[0] == nxt[2] - 2 and candidate[1] == "andaxbx"
            for candidate in img.ops[c.k + 2 :]
        ):
            # Short-circuit gate inside an ungrouped outer AND. The current
            # logical value stays in AX while the right operand is evaluated;
            # its movbxax/movrr spill sequence below preserves and combines it.
            # The far target is the address immediately after that final AND,
            # not a statement boundary (t1_nestedbool; wild styled/hfprop).
            e.direct_bool_gate = True
            state.advance(2)
            return
        if cc == 0x74 and direct_bool and e.direct_bool_gate:
            # Direct-GOTO sibling of the inline-body form: JZ skips the far
            # jump when the completed logical value is false, so the far jump
            # itself is the source THEN target (t1_nestedgoto; wild styled).
            # The materialized outer term is positive evidence for a block
            # IF here: the equivalent one-line direct boolean form has no
            # movax-FFFF header (probe_string_nested_and_or_block).
            if e.direct_bool_logical:
                c.block_if_addrs.add(c.cur)
            state.put(
                ir.IfGoto(
                    (_logical_condition(m.ax) or m.ax)
                    if e.direct_bool_logical
                    else m.ax,
                    ("addr", nxt[2]),
                ),
                c.cur,
            )
            m.ax = None
            e.direct_bool_gate = False
            e.direct_bool_logical = False
            c.cur = None
            state.advance(2)
            return
        if (
            cc == 0x75
            and direct_bool
            # This witnessed inline body ends at a scanned op. A target in the middle
            # of a later materialized expression is a nested short-circuit
            # gate and needs its spill protocol preserved instead.
            and any(candidate[0] == nxt[2] for candidate in img.ops)
        ):
            # A parenthesized logical value can feed JNZ directly: the final
            # AX/BX fold already set ZF, so no separate `or ax,ax` or compare
            # materialization appears.  JNZ skips the following far jump when
            # the value is true; that far jump skips the inline body.  Keep the
            # BinOp/Group tree as a bare truthiness condition: spelling it as
            # `expr = 0` changes both its polarity and TB's lowering.
            state.flush_pending()
            event = state.branch(
                "if",
                template="direct_flag_skip",
                target=nxt[2],
                address=c.cur,
                # The direct flag use is itself evidence that the complete
                # logical value was parenthesized in source; without this
                # outer Group TB chooses its short-circuit IF template.
                cond=(
                    _logical_condition(m.ax) or m.ax
                    if e.direct_bool_logical
                    else m.ax if e.direct_bool_gate else ir.Group(m.ax)
                ),
            )
            c.ifs.append(IfFrame(seq=event.seq, idx=len(out.stmts)))
            m.ax = None
            e.direct_bool_gate = False
            e.direct_bool_logical = False
            c.cur = None
            state.advance(2)
            return
        relop_map = _JCC_RELOP_STR if e.pend_cmp_str else _JCC_RELOP
        if (
            e.pend_cmp
            and nxt
            and nxt[1] in ("jmp", "jmpf")
            and t == nxt[0] + (5 if nxt[1] == "jmpf" else 3)
        ):
            if cc not in relop_map:
                raise ValueError(f"unhandled IF jcc {cc:02x} at {addr:#x}")
            lhs, rhs = e.pend_cmp
            e.pend_cmp = None
            e.pend_cmp_str = False
            # A tail IF closing the procedure has no statement after it to name
            # as the skip target (see DecodeState.open_tail_if). `_JCC_RELOP` /
            # `_JCC_RELOP_STR` give the relop under which the jcc is TAKEN, i.e.
            # the source condition's negation; `_NEGATE_REL` recovers the source
            # polarity for either map.
            if state.open_tail_if(
                nxt[2], ir.RelOp(_NEGATE_REL[relop_map[cc]], lhs, rhs)
            ):
                state.advance(2)
                return
            state.put(
                ir.IfGoto(ir.RelOp(relop_map[cc], lhs, rhs), ("addr", nxt[2])),
                c.cur,
            )
            c.cur = None
            state.advance(2)
            return
        if e.pend_cmp_str:  # string direct conditional GOTO (taken = THEN):
            # forward strcmp flags, so the TRUE map is _JCC_RELOP_STR's inverse
            # (witnessed t1_strgodo `IF A$ = "X" THEN <line>` / wild schart.exe;
            # only "="/"<>" seen, remaining rows by the same forward derivation)
            true_str = _JCC_RELOP_STR_TRUE  # shared with the
            # materialized-as-a-value string path (handlers.control)
            if cc not in true_str:
                raise ValueError(
                    f"string compare jcc {cc:02x} without skip-jmp at {addr:#x}"
                )
            lhs, rhs = e.pend_cmp
            e.pend_cmp = None
            e.pend_cmp_str = False
            state.put(
                ir.IfGoto(ir.RelOp(true_str[cc], lhs, rhs), ("addr", t)),
                c.cur,
            )
            c.cur = None
            state.advance()
            return
        if e.pend_cmp and cc in _JCC_RELOP_TRUE:  # direct conditional GOTO (taken =
            lhs, rhs = e.pend_cmp  # THEN): IF cond THEN <line>, short
            e.pend_cmp = None  # jcc with no skip-jmp (witnessed zz_godo)
            state.put(
                ir.IfGoto(ir.RelOp(_JCC_RELOP_TRUE[cc], lhs, rhs), ("addr", t)),
                c.cur,
            )
            c.cur = None
            state.advance()
            return
        raise ValueError(f"unhandled jcc {cc:02x} at {addr:#x}")
    elif kind in ("jmp", "jmpf"):
        t = op[2]
        frame = c.proc_frame if c.proc_frame is not None else c.fn_frame
        # Near branch targets are canonicalized to their first 64 KiB window
        # by the scanner.  A FOR test can live in a later file window, so use
        # the matching IP nearest this branch (wild electron.exe).
        test_k, cmp_at_t = min(
            (
                (i, candidate)
                for i, candidate in enumerate(img.ops)
                if _same_code_offset(candidate[0], t)
            ),
            key=lambda found: abs(found[1][0] - addr),
            default=(None, None),
        )
        if (
            test_k is not None
            and img.ops[test_k][1] == "fwait"
            and test_k + 1 < len(img.ops)
            and img.ops[test_k + 1][1] == "testw_bp"
        ):  # all-local SINGLE FOR may jump to an x87 synchronization op
            test_k += 1  # immediately before the normal sign-word test
        elif (
            test_k is not None
            and test_k + 2 < len(img.ops)
            and img.ops[test_k][1] == "nop"
            and img.ops[test_k + 1][1] == "nop"
            and img.ops[test_k + 2][1] == "testw_bp"
        ):  # runtime-revision alias of FWAIT, already calibrated for the
            test_k += 2  # integer/FP conversion bridges (wild reformat.exe)
        loose = (
            match_loose_for_header(img.ops, test_k, out.stmts, state.vdisp)
            if test_k is not None
            else None
        )
        if loose is not None:
            lim, stp, vdisp = loose.limit, loose.step, loose.var
            lim_s, stp_s, init_s = out.stmts[-3:]
            with editing(out.stmts, "fold_for_header"):
                del out.stmts[-3:]
            a = out.addrs[-3]
            del out.addrs[-3:]
            state.put(ir.For(init_s.target, init_s.value, lim_s.value, stp_s.value), a)
            if frame is not None and frame.locals is not None:
                # BP-relative limit/step cells are compiler FOR temporaries,
                # not declarations from the source LOCAL statement. Mixed
                # block-DEF-FN loops may use those cells while keeping the
                # loop variable in DGROUP (t1_fnlocalarrstr).
                hidden = {d for d in (lim, stp) if d in frame.locals}
                frame.hidden_locals.update(hidden)
            state.branch(
                "loop", template="for_header", target=img.ops[test_k][0], address=c.cur
            )
            c.fors.append(ForFrame(
                v=vdisp,
                lim=lim,
                stp=stp,
                test=img.ops[test_k][0],
                body=img.ops[c.k + 1][0] if c.k + 1 < len(img.ops) else None,
            ))
        elif match_for_header(out.stmts, state.vdisp) is not None:
            lim_s, stp_s, init_s = out.stmts[-3:]
            del out.stmts[-3:]
            a = out.addrs[-3]
            del out.addrs[-3:]
            v = init_s.target
            state.put(ir.For(v, init_s.value, lim_s.value, stp_s.value), a)
            state.branch(
                "loop", template="for_header", target=t, address=c.cur
            )
            c.fors.append(ForFrame(
                v=state.vdisp(v),
                test=t,
                body=img.ops[c.k + 1][0] if c.k + 1 < len(img.ops) else None,
            ))
        elif (
            cmp_at_t is not None
            and cmp_at_t[1] in ("cmp_mi8", "cmp_mi16", "cmp_bpi8")
            and out.stmts
            and isinstance(out.stmts[-1], ir.Assign)
            and isinstance(out.stmts[-1].target, ir.Var)
            and cmp_at_t[2] == state.vdisp(out.stmts[-1].target)
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
            with editing(out.stmts, "fold_for_header"):
                init_s = out.stmts.pop()
            a = out.addrs.pop()
            state.put(
                ir.For(init_s.target, init_s.value, ir.Lit(cmp_at_t[3]), ir.Lit(1)),
                a,
            )
            if cmp_at_t[1] == "cmp_bpi8" and c.proc_frame is not None:
                # A literal-bound FOR over a LOCAL reserves two unused
                # limit/step temp words in the LOCAL frame (the frame analog of
                # the static band's phantom slots, q_forstep) -- they are not
                # declared LOCALs (q_locidx). A literal bound leaves NO op
                # referring to either temp, so there is nothing to anchor them
                # to and the offsets can only be guessed positionally; stage
                # the guess and let proc_ret drop it only if the body never
                # touched it (see touch_local -- the compiler actually puts the
                # temps at the frame TAIL, so `v+2`/`v+4` are real declared
                # LOCALs whenever the loop var is not the last one declared,
                # t1_locstrafterforlit).
                c.proc_frame.has_local_for = True
            state.branch(
                "loop", template="for_header", target=t, address=c.cur
            )
            c.fors.append(ForFrame(
                v=cmp_at_t[2],
                test=t,
                idx=len(out.stmts) - 1,
                step=1,
                body=img.ops[c.k + 1][0] if c.k + 1 < len(img.ops) else None,
            ))
        elif (
            cmp_at_t is not None
            and cmp_at_t[1] in ("movax_m", "movax_bp")
            and out.stmts
            and isinstance(out.stmts[-1], ir.Assign)
            and isinstance(out.stmts[-1].target, ir.Var)
            and isinstance(out.stmts[-1].value, ir.Lit)
            and (nxt_t := next((o for o in img.ops if o[0] > t), None)) is not None
            and nxt_t[1]
            == {"movax_m": "cmpm_ax", "movax_bp": "cmpm_ax_bp"}[cmp_at_t[1]]
            and nxt_t[2] == state.vdisp(out.stmts[-1].target)
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
            with editing(out.stmts, "fold_for_header"):
                init_s = out.stmts.pop()
            a = out.addrs.pop()
            limit = (
                state.loc_local(cmp_at_t[2])
                if cmp_at_t[1] == "movax_bp"
                else state.loc(cmp_at_t[2])
            )
            if (
                out.stmts
                and isinstance(out.stmts[-1], ir.Assign)
                and isinstance(out.stmts[-1].target, ir.Var)
                and state.vdisp(out.stmts[-1].target) == cmp_at_t[2]
            ):
                with editing(out.stmts, "fold_for_header"):
                    limit = out.stmts.pop().value
                a = out.addrs.pop()
            if cmp_at_t[1] == "movax_bp" and c.proc_frame is not None:
                # A variable-limit FOR over a LOCAL reserves the SAME
                # [step-temp, limit-temp] word pair as the literal-limit
                # case above -- the step-temp is unused with a literal step
                # and dropped immediately, but the limit-temp (== cmp_at_t[2])
                # is read again at every iteration's test (movax_bp reloads
                # it), so it can't be dropped yet; stash it and strip it
                # only once the SUB body is fully decoded (proc_ret),
                # mirroring the variable-STEP LOCAL case's step-temp
                # handling above.
                #
                # Anchor the pair to the LIMIT-temp (step == limit - 2), the
                # way the by-ref-loop-var sibling below already does. The
                # temps go at the END of the frame, NOT right after the loop
                # var: `v + 2` only coincides with them when the loop var is
                # the last declared LOCAL, as in t1_locforvarlim. Declare
                # anything after it -- `LOCAL I%, S$` -- and v+2 is a REAL
                # local, silently deleted from the frame table here, so its
                # own later access raised `string [bp+N] outside the open
                # LOCAL frame` (t1_locstrafterfor; wild tbd73.exe's TBWINDOW
                # `SUB Makevmenu`, whose `LOCAL done, mloop, ans$, ans1$` puts
                # the string descriptor ans$ exactly at mloop+2). The step-temp
                # rides the frame-tail retirement instead of being deleted
                # here; the limit-temp IS anchored (movax_bp names it) and so
                # stays unconditional.
                c.proc_frame.has_local_for = True
                c.proc_frame.hidden_locals.add(
                    cmp_at_t[2]
                )
            state.put(
                ir.For(init_s.target, init_s.value, limit, ir.Lit(1)),
                a,
            )
            state.branch(
                "loop", template="for_header", target=t, address=c.cur
            )
            c.fors.append(ForFrame(
                v=nxt_t[2],
                test=t,
                idx=len(out.stmts) - 1,
                body=img.ops[c.k + 1][0] if c.k + 1 < len(img.ops) else None,
            ))
        elif (
            cmp_at_t is not None
            and cmp_at_t[1] == "movax_bp"
            and out.stmts
            and isinstance(out.stmts[-1], ir.Assign)
            and isinstance(out.stmts[-1].target, ir.Var)
            and isinstance(out.stmts[-1].value, ir.Lit)
            and (nxt_t := next((o for o in img.ops if o[0] > t), None)) is not None
            and nxt_t[1] == "arg_ref"
            and (nxt_t2 := next((o for o in img.ops if o[0] > nxt_t[0]), None))
            is not None
            and nxt_t2[1] == "far_cmpm_ax_si"
            and nxt_t[2] == state.vdisp(out.stmts[-1].target)
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
            with editing(out.stmts, "fold_for_header"):
                init_s = out.stmts.pop()
            a = out.addrs.pop()
            limit = state.loc_local(cmp_at_t[2])
            if (
                out.stmts
                and isinstance(out.stmts[-1], ir.Assign)
                and isinstance(out.stmts[-1].target, ir.Var)
                and state.vdisp(out.stmts[-1].target) == cmp_at_t[2]
            ):
                with editing(out.stmts, "fold_for_header"):
                    limit = out.stmts.pop().value
                a = out.addrs.pop()
            if c.proc_frame is not None:
                # Step-temp rides the frame-tail retirement (see the movax_bp
                # sibling above); limit-temp is anchored by cmp_at_t itself.
                c.proc_frame.has_local_for = True
                c.proc_frame.hidden_locals.add(
                    cmp_at_t[2]
                )
            state.put(
                ir.For(init_s.target, init_s.value, limit, ir.Lit(1)),
                a,
            )
            state.branch(
                "loop", template="for_header", target=t, address=c.cur
            )
            c.fors.append(ForFrame(
                v=nxt_t[2],
                test=t,
                idx=len(out.stmts) - 1,
                body=img.ops[c.k + 1][0] if c.k + 1 < len(img.ops) else None,
            ))
        elif (
            cmp_at_t is not None
            and cmp_at_t[1] == "orax_self"
            and img.ops[c.k - 1][1] in ("movax_m", "movax_bp")
            and len(out.stmts) >= 2
            and isinstance(out.stmts[-1], ir.Assign)
            and isinstance(out.stmts[-1].target, ir.Var)
            and isinstance(out.stmts[-1].value, ir.Lit)
            and isinstance(out.stmts[-2], ir.Assign)
            and isinstance(out.stmts[-2].target, ir.Var)
            and state.vdisp(out.stmts[-2].target) == img.ops[c.k - 1][2]
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
            with editing(out.stmts, "fold_for_header"):
                init_s = out.stmts.pop()
            a = out.addrs.pop()
            with editing(out.stmts, "fold_for_header"):
                step_s = out.stmts.pop()
            out.addrs.pop()
            if img.ops[c.k - 1][1] == "movax_bp" and c.proc_frame is not None:
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
                c.proc_frame.hidden_locals.update(
                    (step_disp, step_disp + 2)
                )
            state.put(
                ir.For(init_s.target, init_s.value, ir.Lit(0), step_s.value),
                a,
            )
            state.branch(
                "loop", template="for_header", target=t, address=c.cur
            )
            c.fors.append(ForFrame(
                v=state.vdisp(init_s.target),
                test=t,
                idx=len(out.stmts) - 1,
                var_step=True,
                body=img.ops[c.k + 1][0] if c.k + 1 < len(img.ops) else None,
            ))
        elif frame is not None and t in (
            frame.exit,
            frame.teardown_entry,
        ):  # jmp to ProcRet/FnRet (or its LOCAL-string teardown) = EXIT SUB/DEF
            exit_stmt = ir.ExitSub() if c.proc_frame is not None else ir.ExitDef()
            if (
                out.stmts
                and isinstance(out.stmts[-1], ir.IfGoto)
                and isinstance(out.stmts[-1].target, tuple)
            ):
                c.exit_folds.append((exit_stmt, out.stmts[-1].target[1], t))
                state.put(ir.Goto(("addr", t)), c.cur)
            else:  # bare (unconditional) EXIT SUB/DEF (witnessed t1_subgsb)
                state.put(exit_stmt, c.cur)
        else:
            state.put(ir.Goto(("addr", t)), c.cur)
        c.cur = None
    elif kind == "call":
        state.put(ir.Gosub(("addr", op[2])), c.cur)
        c.cur = None
    elif kind in ("ret", "retf"):  # retf = RETURN under event trapping
        state.put(ir.Return(), c.cur)
        c.cur = None
    elif kind == "return_to":
        state.put(ir.Return(("addr", op[2])), c.cur)
        c.cur = None
    elif kind == "run":
        state.put(ir.Run(), c.cur)
        c.cur = None
    elif kind == "jmps":
        nxt = img.ops[c.k + 1] if c.k + 1 < len(img.ops) else None
        # Asked once, against the list as the queued folds will leave it: every
        # branch below means the folded list, which is what the eager fold
        # handed them for free.
        back_idx = state.statement_index(op[2])
        if (
            c.dos and op[2] == c.dos[-1].test
        ):  # head-test DO ... LOOP back-edge
            f = c.dos.pop()
            if nxt is None or nxt[0] != f.exit:
                raise ValueError(f"LOOP exit mismatch at {addr:#x}")
            state.put(ir.Loop(None), c.cur)
        elif (
            c.whiles and op[2] == c.whiles[-1].test
        ):  # legacy WHILE ... WEND
            f = c.whiles.pop()
            if nxt is None or nxt[0] != f.exit:
                raise ValueError(f"WEND exit mismatch at {addr:#x}")
            state.put(ir.Wend(), c.cur)
        elif op[2] < addr and back_idx is not None:  # bare backward jmps = infinite DO
            idx = back_idx  # splice `DO` before the body start
            with editing(out.stmts, "fold_loop_header"):
                out.stmts.insert(idx, ir.Do(None))
            out.addrs.insert(idx, None)
            state.shift_pending(idx, 1)
            state.put(ir.Loop(None), c.cur)
            # EXIT LOOP: a GOTO past the LOOP (to nxt) is an exit; the conditional that
            # skips it jumps to the LOOP back-edge (this jmps' addr). Fold at epilogue.
            if nxt is not None:
                c.exit_folds.append((ir.ExitLoop(), addr, nxt[0]))
        elif op[2] < addr and (
            op[2] in out.stmt_addr.values() or op[2] in state.folded_away
        ):
            # short GOTO to a NUMBERED line inside an already-folded block-IF
            # body (TB allows jumping into a block interior when the interior
            # line carries a number -- witnessed t1_blkgoto / wild inv87.exe);
            # resolves to ir.BodyLine at finalize
            state.put(ir.Goto(("addr", op[2])), c.cur)
        elif op[2] == addr - 1:
            # Empty event-polling DO...LOOP: the only body byte is the hook
            # immediately before this short back edge (wild baby.exe, TB 1.0).
            state.put(ir.Do(None), c.cur)
            state.put(ir.Loop(None), None)
        else:
            raise ValueError(f"unhandled jmp short at {addr:#x}")
        c.cur = None
    else:
        raise ValueError(f"unhandled op {kind} at {addr:#x}")
    state.advance()


def _decode_user_code(
    exe: bytes, *, diagnostics: DecodeDiagnostics | None = None
) -> list[Any]:
    """Decode from the prologue to (and including) END. Returns typed IR statements with
    canonical variable names and statement-index jump targets."""
    state = DecodeState(diagnostics=diagnostics)
    img, m, e, l, c, out = (state.image, state.machine, state.expr,
                            state.layout_state, state.control, state.output)
    state.validate_ownership()
    img.exe = exe
    img.start, img.dia = find_prologue(exe)
    out.metas = _meta_stmts(
        exe, img.start
    )  # read now: `start` is rebound downstream
    out.toggles = _toggles(exe, img.start)
    out.commits = set()
    img.ops = _scan(exe, img.start, img.dia, out.commits)
    # TRON trace hooks are per-LINE position markers, not statements: fold each
    # out of the op stream, re-stamping the FOLLOWING op with the hook's address
    # (uniform "hooks keep cur" semantics -- statement starts land on the hook,
    # so jump targets and the hook+4 alias behave as before) so that multi-op
    # recognizers (IF folds, SELECT CASE) see uninterrupted patterns
    # (t1_tronif/t1_troncase). Consecutive hooks are code-less source lines
    # (END IF): they share the stamp address; trace_tbl keeps the LAST line for
    # the statement pin and hook_seq keeps ALL lines in order -- emit0 numbers
    # one physical line per hook inside traced statements.
    out.trace_tbl = {}  # hook stamp addr -> line number (last wins)
    out.hook_seq = []  # every hook line, in address order
    if any(o[1] == "trace_hook" for o in img.ops):
        ops2, pend_hook, alias = [], None, {}
        for o in img.ops:
            if o[1] == "trace_hook":
                h = o[0] if pend_hook is None else pend_hook
                out.trace_tbl[h] = o[2]
                out.hook_seq.append(o[2])
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
        img.ops = []
        for o in ops2:
            if o[1] in ("jmp", "jmps") or (o[1] == "on_error" and o[2] is not None):
                o = (o[0], o[1], alias.get(o[2], o[2]))
            elif o[1] in ("jcc", "on_trap"):
                o = o[:3] + (alias.get(o[3], o[3]),)
            img.ops.append(o)
    # The same hook-blindness for EVENT-trap hooks, which (unlike trace hooks)
    # stay in the stream: a code-less source line (END IF) still gets its own
    # per-statement CC hook, so hooks pile up back-to-back ahead of the next
    # real statement. `c.cur` takes the FIRST hook of such a run and keeps
    # it, so that is the statement's address -- but the compiler's own block-IF
    # arm tails jump to the LAST one, which then matches no statement and left
    # the fold undone (a bare Goto surviving into _resolve_targets). Normalize
    # those targets onto the run's first hook: every hook in a run precedes the
    # same statement, so they resolve identically (probe t1_dblhook; wild
    # rsltest.exe's TBWINDOW IF/ELSEIF/ELSE chain).
    hook_alias, entry_hook, run_first = {}, {}, None
    for i, o in enumerate(img.ops):
        if o[1] != "trap_hook":
            run_first = None
        elif run_first is None:
            run_first = o[0]
            if i + 1 < len(img.ops) and img.ops[i + 1][1] != "trap_hook":
                entry_hook[img.ops[i + 1][0]] = o[0]
        else:
            hook_alias[o[0]] = run_first
    if hook_alias or entry_hook:
        ops3 = []
        for o in img.ops:
            if o[1] in ("jmp", "jmps") or (o[1] == "on_error" and o[2] is not None):
                target = entry_hook.get(o[2], o[2])
                o = (o[0], o[1], hook_alias.get(target, target))
            elif o[1] in ("jcc", "on_trap"):
                target = entry_hook.get(o[3], o[3])
                o = o[:3] + (hook_alias.get(target, target),) + o[4:]
            ops3.append(o)
        img.ops = ops3
    l.lay = _layout(exe, img.ops)
    l.ds = l.lay["ds"]
    l.dsd = (
        l.ds - l.lay["delta"]
    )  # file base for pool/descriptor/string reads
    l.arrs = l.lay["arrs"]  # static arrays (unified slot records)
    # Unified slot registry for the far/near index machine: static slots prefilled
    # from their records; runtime blocks register at their DIM bracket.
    # ...keyed at the grid's REAL start: `var_base` normally, but under COMMON
    # the band pushes the statics out past it, and keying them at var_base put
    # phantom slots on top of the COMMON blocks' own addresses -- a phantom's
    # 0x36 window then shadowed a real block in the far-IDX lookups (wild
    # tbd73.exe: slot 0x1c2 swallowed block 0x1e8's `lo1` cell).
    l.slot_info = {
        l.lay["static_base"] + ARR_BLOCK * i: a for i, a in enumerate(l.arrs)
    }
    for a in l.arrs:
        if a["str"] and not a["name"].endswith("$"):
            a["name"] += "$"  # element type from the record
        if a["long"] and not a["name"].endswith("&"):
            a["name"] += "&"  # long-integer arrays render with `&`
        if a.get("int") and not a["name"].endswith("%"):
            a["name"] += "%"  # integer arrays (type 00, esz 2) render with `%`
        if a.get("dbl") and not a["name"].endswith("#"):
            a["name"] += "#"  # double arrays (type 06, esz 8) render with `#`
    e.stack = []  # the emulated FP stack, as ir Expr nodes
    out.stmts = RecordedStatements()
    # Interleave the two logs: an edit records where in the event
    # stream it happened, so a branch's list position is recoverable.
    out.stmts.clock = lambda: len(state.events)
    out.addrs = []  # addrs[k] = first-op address of stmts[k]
    out.stmt_addr = AddressOwnership()  # statement -> its op address, retained
    # fold (which drops body addrs) so the TRON lift can find
    # a region that ends INSIDE a block body (t1_troffin)
    c.cur = None  # start address of the statement being built
    e.pend_cmp = None  # (lhs_expr, rhs_expr) from FLD y; FCOMP [x]
    c.fors = []  # open FOR frames
    c.whiles = []  # open WHILE frames
    c.dos = []  # open head-test DO frames (DO WHILE/UNTIL ... LOOP)
    c.exit_folds = []  # (exit_stmt, skip_addr, exit_addr): EXIT FOR/LOOP folds
    c.cases = []  # open SELECT CASE frames (Task 3.4)
    m.ax = None  # the integer accumulator, as an ir Expr
    m.bx = None  # LOCATE's row register / int right operand
    m.dx = None  # IMP's left operand register
    e.pend_icmp = None  # (lhs, rhs) from cmp ax,[m]: relational value
    out.cc_hooks = set()  # CC event-poll hook addrs ($EVENT regions)
    m.cint_round = False  # fistp[2C]..fild[2C] round-trip = CINT(x)
    e.color_cells = {}  # pending COLOR stores: cell disp -> Lit
    e.sstack = []  # the string operand stack
    e.pend_input = None  # (prompt Expr|None, flags) awaiting its read call
    e.pend_line_input = None  # (prompt, semi) awaiting a LINE INPUT read
    e.pend_fnum = None  # file number from the [0060] cell
    l.dim_frame = None  # open runtime-DIM bracket
    l.local_dim_frame = None  # open LOCAL-frame (heap-allocated) DIM bracket
    l.n_local_arrs = 0  # V# numbering tail for LOCAL DYNAMIC arrays
    l.prev_dim_end = None  # last allocate's addr: comma-chain test
    l.r_arrs = {}  # block disp -> runtime array info
    m.fp64_bridge = {}  # transient sub-VAR_BASE fstp64/fld64 scratch cache
    # (promote-once/compare-many idiom, e.g. `IF N%=1 THEN...ELSEIF N%=2
    # THEN...` promotes N% to DOUBLE once and rereads the cache for each
    # comparison -- the same "stage, then reread" shape as the fistp[0x2C]
    # IDX% bridge, just for a variable-position scratch cell instead of a
    # fixed one; wild resume.exe)
    l.option_base = None  # 0/1 from DIM lower-bound cells
    m.pend_es = None  # block disp loaded into ES (far access)
    e.pend_shortstr = None  # packed 1-char string awaiting `shortstr`
    e.pend_mode_lit = None  # OPEN's FOR-keyword mode, once materialized
    e.pend_swap = None  # first ArrayRef of an ES-aliased array-element SWAP
    e.pend_swap_rev = None  # first far ArrayRef of the reverse dynamic SWAP
    m.cx = None  # 2nd-level index stash / WAIT and-mask
    m.di = None  # 3rd-level spill stash for nested integer expressions
    m.si = None  # element-index register (raw index / idx token)
    m.reg_spills = {}  # scratch-cell saves used beyond the register spill chain
    # Expression identities produced by register-register logical folds.  The
    # identity follows a value through movbxax/movrr without making every
    # generic register assignment maintain a separate provenance flag.
    e.reg_logical_results = []
    e.bchk_subs = []  # Bounds: pending non-final subscripts (F3.5)
    e.bchk_bp = None  # Bounds: open BP-relative LOCAL-array descriptor
    e.pend_bool = None  # compound-IF first term awaiting its tail
    e.pend_bool_outer = None  # enclosing accumulator awaiting a deferred
    # inner mixed-precedence group's own close (A OR B AND C's "A OR")
    e.pend_print = None  # open PRINT item chain
    e.pend_using = None  # open PRINT USING value chain
    e.pend_filein = None  # open INPUT# target chain
    e.pend_getstr = None
    e.pend_dataread = None  # open READ target chain
    e.pend_field = None  # open FIELD AS-entry chain
    c.ifs = []  # open inline-IF bodies
    c.pending_ifs = []  # regions whose extent is known, waiting to be folded
    c.fold_plan = []  # every such region, kept after the fold consumes it
    c.block_if_addrs = set()  # statement addrs whose BYTES prove the
    # source spelled a multi-line block IF (see lift._lift_while)
    c.has_procs = any(
        o[1] in ("proc_enter", "fn_ret", "inline_sub", "opaque_helper")
        for o in img.ops
    )  # def region present
    c.proc_names = {}  # proc entry addr -> synthesized name (SUB1.., FNFN1..)
    c.proc_params = {}  # SUB entry addr -> params tuple (declaration order),
    # for typing forwarded by-ref args at nested CALL sites (q_fwd)
    # open SUB body {entry, idx} (idx into stmts) / open DEF FN body {.., result, max_off}
    c.proc_frame = None
    c.fn_frame = None
    c.fn_args = {}  # staged FN-call args: bp_off -> Expr (offset-ordered)
    c.fn_args_stack = []  # nested-call-as-argument scoping for fn_args,
    # the DEF FN sibling of sp_save_stack below: a DEF FN call used as its OWN
    # outer DEF FN call's argument must not drain/clear the outer's
    # partially-staged fn_args when the inner call's own fn_call runs
    # (t1_fnargcall; unlike SUB CALL, which is a statement and structurally
    # can't nest as an argument, DEF FN calls are expressions and can)
    img.main_start = None  # def-region end = entry-jmp target
    out.seg_metas = []  # stmt indices where a $SEGMENT transition landed
    c.inline_procs = set()  # entry addrs of SUB ... INLINE definitions
    c.fwd_inline_offs = set()  # bp offsets forwarded to one of them
    c.nsub = 0  # SUB counter (entry-offset order)
    c.nfn = 0  # DEF FN counter (entry-offset order)
    c.pend_arg = None  # by-ref param bp_off from arg_ref (les si,[bp+N])
    c.pend_args = []  # accumulated CALL args, drained by far_call
    c.sp_save_cell = None  # cell holding saved SP (literal-arg staging)
    c.sp_save_stack = []  # nested call-staging frames: a call used as its
    # OWN outer call's argument opens a new push_bp/mov_mem_sp/.../pop_bp
    # region before the outer's own movm_imm-glue cell is reached (wild
    # resume.exe) -- restored on the matching pop_bp
    c.proc_str_offs = (
        set()
    )  # bp_offs the open proc reads as strings (arg_ref;far_spush)
    c.proc_int_offs = set()  # bp_offs read as integers (far_cmpax_si)
    c.proc_long_offs = set()  # bp_offs read as LONG (far_fild_si32 etc.)
    c.proc_dbl_offs = set()  # bp_offs read as DOUBLE (far_fld_si64 etc.)

    # String-space base: ss_base = align16(pool end), but the pool can
    # hold words the code never references (LOCATE/COLOR arg literals compile to
    # immediates yet are still pooled), so a reference-based estimate undershoots.
    # Anchor it instead on the char record itself, which is bracketed on BOTH sides by
    # the word (sum_of_string_lens | 0x8000) with 4 zero bytes after the leading one:
    # ds+ss_base+0x10: <hdr> 00 00 00 00 <chars...> <hdr>.
    l.ss_base = None
    # Pooled literal descriptors: movsi targets that aren't var slots, plus INPUT /
    # LINE INPUT prompt words (excluding the resident empty-string desc and
    # constant far-element offsets).
    l.desc_disps = sorted(
        (
            {
                img.ops[i][2]
                for i in range(len(img.ops))
                if img.ops[i][1] == "movsi"
                and img.ops[i][2]
                >= VAR_BASE  # sub-VAR_BASE = scratch (SELECT CASE str temp)
                and not (
                    i + 1 < len(img.ops)
                    and img.ops[i + 1][1]
                    in ("far_spush", "far_strassign", "add_si_sp")
                )
            }
            - set(l.lay["scalars"])
            - set(l.lay["rt_blocks"])
            - set(l.slot_info)
        )  # GET/PUT blit array-slot pushes (t1_getput)
        | {
            o[2]
            for o in img.ops
            if o[1] in ("input", "line_input") and o[2] != l.lay["pool_base"] - 4
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
    l.discard_strs = []
    l.data_items = []
    l.have_fre = any(o[1] == "fre_str" for o in img.ops)
    if l.desc_disps or l.have_fre:
        all_descs = []
        d = l.lay["pool_base"] - 4
        w0, expect = struct.unpack_from("<HH", exe, l.dsd + d)
        if w0 == 0x8000:  # resident empty desc anchors the walk
            d += 4
            while True:
                w0, ptr = struct.unpack_from("<HH", exe, l.dsd + d)
                if not w0 & 0x8000 or ptr != expect:
                    break
                all_descs.append((d, w0 & 0x7FFF, ptr))
                expect = ptr + (w0 & 0x7FFF)
                d += 4
        if all_descs:
            total = sum(ln for _, ln, _ in all_descs)
        else:  # no walkable table: referenced sum as before
            total = sum(
                struct.unpack_from("<H", exe, l.dsd + d)[0] & 0x7FFF
                for d in l.desc_disps
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
            pos = l.dsd + cand + 0x10
            if (
                exe[pos : pos + 2] == hdr
                and exe[pos + 2 : pos + 6] == b"\x00\x00\x00\x00"
                and exe[pos + 6 + total : pos + 8 + total] == hdr
            ):
                l.ss_base = cand
                break
        else:
            raise ValueError("string char record not found")
        unref = [(ln, ptr) for d, ln, ptr in all_descs if d not in l.desc_disps]
        if unref:
            if not l.have_fre:
                # Unreferenced descriptors without FRE sites are DATA items.
                # The shared literal pool stores them in reverse source order;
                # code-referenced literals were removed by desc_disps above.
                for ln, ptr in reversed(unref):
                    text = exe[
                        l.dsd + l.ss_base + ptr : l.dsd
                        + l.ss_base
                        + ptr
                        + ln
                    ].decode("latin-1")
                    try:
                        float(text)
                        is_str = False
                    except ValueError:
                        is_str = True
                    l.data_items.append(ir.DataItem(text, is_str))
            else:
                l.discard_strs = [
                    ir.StrLit(
                        exe[
                            l.dsd + l.ss_base + ptr : l.dsd
                            + l.ss_base
                            + ptr
                            + ln
                        ].decode("latin-1")
                    )
                    for ln, ptr in reversed(unref)
                ]

    state.begin(img.ops)
    while c.k < len(img.ops):
        # Every handler now commits through ``state.advance``/``state.seek``,
        # so the cursor is already at ``c.k`` here.  The sync stays as the
        # cheap guard that says so: it raises if some path moved the index
        # without the cursor witnessing the operations it crossed.
        assert state.cursor is not None
        state.cursor.sync(c.k)
        op = img.ops[c.k]
        addr, kind = op[0], op[1]
        assert state.diagnostics is not None
        state.diagnostics.observe(
            state.cursor,
            address=addr,
            statement=c.cur,
        )
        if kind == "nop":
            state.advance()
            continue
        if kind == "into":
            # Overflow-toggle check (0xCE, no operand): the compiler inserts
            # this after arithmetic that could overflow when the 'O' IDE
            # Options toggle is on. No source spelling (rides on
            # Program.toggles like Bounds/Stack test) and no IR effect --
            # skip in place, mid-expression, without disturbing c.cur
            # (witnessed q_ovf).
            state.advance()
            continue
        if kind == "stack_chk":
            # Stack-test toggle ('S') room check before a CALL: cmp sp against
            # a callee-dependent threshold, raise error 7 if short. No source
            # spelling and no IR effect -- skip like "into" (witnessed q_stsub).
            state.advance()
            continue
        # Before any fold runs -- select_case closes its arms here too -- so the
        # list length at this event is the extent of every region ending here.
        state.arrive(addr)
        if select_case.step(state):
            continue
        state.close_ifs(addr)
        if kind == "segjmp":
            # The far jump is the source-level `$SEGMENT` metacommand.  Its
            # selector is a compiler allocation detail, not a discriminator:
            # t1_segment happens to receive 2, while TBWINDOW/tbd73's authored
            # `$SEGMENT` receives 30 after its larger pre-directive region.
            out.seg_metas.append(len(out.stmts))
            state.advance()
            continue
        # --- procedure-region segmentation ---
        if c.has_procs and c.k == 0 and kind == "jmp":
            img.main_start = op[
                2
            ]  # entry jmp over the def region: target = main start
            state.advance()  # glue, not a GOTO
            continue
        if (
            c.has_procs
            and kind == "jmp"
            and img.main_start is None
            and c.fn_frame is None
            and c.proc_frame is None
            and len(out.stmts) == 1
            and isinstance(out.stmts[0], ir.OnError)
        ):
            # `ON ERROR GOTO` as the program's very first statement, ahead
            # of the entry skip-jmp (wild wb.exe): the k==0 case above
            # assumes the skip-jmp IS op 0, but a real leading statement can
            # precede it. Recognized narrowly (exactly one prior statement,
            # and it's ON ERROR) rather than generically allowing any
            # leading statement, since a real early GOTO must not be
            # swallowed as glue.
            img.main_start = op[2]
            state.advance()  # glue, not a GOTO
            continue
        if (
            c.has_procs
            and kind == "jmp"
            and c.fn_frame is None
            and c.proc_frame is None
            and c.k > 0
            and img.ops[c.k - 1][1] == "end"
            and (
                any(
                    o[0] == op[2] and o[1] == "epilogue"
                    for o in img.ops[c.k + 1 :]
                )
                or any(
                    img.ops[i][0] == op[2]
                    and img.ops[i][1] == "jmp"
                    and i + 1 < len(img.ops)
                    and img.ops[i + 1][1] == "proc_enter"
                    for i in range(c.k + 1, len(img.ops))
                )
            )
        ):
            # Main code can precede a trailing SUB definition. END is followed
            # by compiler skip-jump glue over that body, either directly to
            # the epilogue or to the next chained definition's skip-jump; it
            # has no source GOTO spelling (probe arrayparam6; wild zip.exe).
            img.main_start = op[2]
            state.advance()
            continue
        if (
            c.has_procs
            and kind == "jmp"
            and img.main_start is None
            and c.fn_frame is None
            and c.proc_frame is None
            and c.k > 0
            and c.k + 1 < len(img.ops)
            and img.ops[c.k + 1][1]
            in ("proc_enter", "inline_sub", "opaque_helper")
        ):
            # Same entry skip-jmp as the k==0 case above, but the definitions
            # do not open the program: ordinary main code runs first and simply
            # FALLS INTO the def region with no END to close it, so neither the
            # k==0 case (op 0 is that main code) nor the END case just above
            # fires. The jmp sits immediately before the first definition's own
            # entry op, which is what distinguishes it from a real GOTO written
            # right before a SUB -- there the user's jmp and the compiler's skip
            # are two separate ops (probe t1_declnoend; wild rsltest.exe, whose
            # DIM block precedes a $INCLUDE'd TBWINDOW definition run).
            img.main_start = op[2]
            state.advance()  # glue, not a GOTO
            continue
        if (
            c.has_procs
            and kind == "jmp"
            and addr == img.main_start
            and c.k + 1 < len(img.ops)
            and img.ops[c.k + 1][1]
            in ("proc_enter", "inline_sub", "opaque_helper", "mov_bp_imm")
        ):  # chained skip-jmp: consecutive SUB defs are each bracketed by
            # their own jmp, so the entry jmp lands on the next def's jmp;
            # extend the def region to its target (witnessed q_fwd; the
            # inline_sub sibling is probe q_shriek's `SUB ... INLINE`).
            # A block DEF FN has no proc_enter of its own, so when the chain
            # reaches one the next op is instead its `mov [bp+0],0` result-slot
            # zero-fill -- safe to accept here because `addr == main_start`
            # already pins this jmp to exactly where the previous hop landed
            # (probe t1_inlinethendef; wild tbd73.exe, whose TBWINDOW DEF FN
            # run follows the inline SUBs)
            img.main_start = op[2]
            state.advance()  # glue, not a GOTO
            continue
        if (
            c.has_procs
            and kind == "jmp"
            and c.fn_frame is None
            and c.proc_frame is None
            and c.k > 0
        ):
            j = c.k - 1
            while j >= 0 and img.ops[j][1] == "trap_hook":
                j -= 1  # event-trapping stamps sit between the closer and the jmp
            if j < 0 or img.ops[j][1] in ("proc_ret", "fn_ret"):
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
                img.main_start = op[2]
                state.advance()  # glue, not a GOTO
                continue
        if kind == "inline_sub":  # SUB name INLINE: the compiler copies
            # $INLINE's byte list verbatim with NO proc_enter/proc_ret
            # framing at all (see _try_inline_rescue in scan.py) -- no
            # params, no body statements to accumulate, so unlike every
            # other procedure this is complete in one op (probe q_shriek).
            c.nsub += 1
            name = f"SUB{c.nsub}"
            c.proc_names[addr] = name
            c.proc_params[addr] = ()
            c.inline_procs.add(addr)  # declares no parameter list at all
            out.stmts.append(ir.SubDef(name, (), (ir.Inline(op[2]),)))
            out.addrs.append(None)  # a SUB definition is never a jump target
            c.cur = None
            state.advance()
            continue
        if kind == "opaque_helper":
            # Coverage-only recovery for a fully fingerprinted framed helper.
            # Its declaration-order parameter offsets are known from the BP
            # frame, but its source semantics and parameter types are not.
            c.nsub += 1
            name = f"SUB{c.nsub}"
            params = tuple(f"P{off:02X}" for off in op[3])
            c.proc_names[addr] = name
            c.proc_params[addr] = params
            out.stmts.append(ir.SubDef(name, params, (ir.OpaqueHelper(op[2]),)))
            out.addrs.append(None)
            c.cur = None
            state.advance()
            continue
        # A DEF FN body has no proc_enter prologue (terminated by fn_ret): the first
        # op in the def region with no open frame opens one.
        if (
            c.has_procs
            and c.fn_frame is None
            and c.proc_frame is None
            and img.main_start is not None
            and addr < img.main_start
            and kind != "proc_enter"
        ):
            fn_exit = next(o[0] for o in img.ops[c.k :] if o[1] == "fn_ret")
            c.fn_frame = FnFrame(
                entry=addr,
                # A DEF FN body has no proc_enter to record its extent, so it
                # records one here, where the frame opens (see proc_enter).
                seq=state.region("fn", start=addr, end=fn_exit).seq,
                idx=len(out.stmts),
                exit=fn_exit,
            )
            c.cur = None  # fall through to lift this op into the body
        if kind == "proc_enter":
            state.flush_pending()
            body = match_proc_body(img.ops, c.k)
            if body is None:
                raise state.error(
                    f"SUB/DEF FN body at {addr:#x} has no proc_ret",
                    component="control",
                )
            c.proc_frame = ProcFrame(
                entry=addr,
                # The body's own region, recorded before a statement of it is
                # committed: the fold at proc_ret reads its start position back
                # out of the log rather than off this frame.
                seq=state.region("proc", start=addr, end=body.exit_address).seq,
                idx=len(out.stmts),
                exit=body.ret_address,
                exit_entry=body.exit_address,
            )
            c.proc_str_offs = set()
            c.proc_int_offs = set()
            c.proc_long_offs = set()
            c.proc_dbl_offs = set()
            c.cur = None
            state.advance()
            continue
        if kind == "local_init":  # LOCAL statement's zero-fill prologue
            frame = (
                c.proc_frame if c.proc_frame is not None else c.fn_frame
            )
            if frame is None or len(out.stmts) != frame.idx:
                raise ValueError(
                    f"LOCAL zero-fill outside a fresh SUB/DEF FN body at {addr:#x}"
                )
            cnt, disp = op[2], op[3]
            frame.locals = {
                disp + 2 * i: f"L{disp + 2 * i:02X}%" for i in range(cnt)
            }
            frame.local_span = (disp, cnt)  # _retire_for_temps needs the
            # zero-filled extent to find the frame TAIL, where a LOCAL FOR's
            # temp words actually live
            if c.proc_frame is not None:
                c.proc_frame.frame_words = cnt  # retf pop math needs the
                # full zero-filled span even after FOR temp words are dropped
                # from the dict (q_locidx) -- a SUB-only concern: DEF FN's
                # fn_ret closing has no analogous pop-count computation
            c.cur = None
            state.advance()
            continue
        if (
            kind == "mov_bp_imm"
            and l.local_dim_frame is None
            and c.k + 3 < len(img.ops)
            and img.ops[c.k + 1][1] == "mov_bp_imm"
            and img.ops[c.k + 2][1] == "far_ref_bp"
            and img.ops[c.k + 3][1] == "dim_begin"
            and img.ops[c.k + 2][2] == op[2] - 2
            and img.ops[c.k + 1][2] == op[2] + 4
        ):  # LOCAL DYNAMIC array (`LOCAL A()` + runtime `DIM A(n)`): opens
            # with a duplicate type/rank + element-size write (re-written
            # again once dim_begin/dim_end brackets the bound cells below),
            # then the LOCAL-frame sibling of the ordinary movsi/movdx/
            # movesdx-fronted DGROUP $DYNAMIC bracket, keyed by frame disp
            # instead of a DGROUP block (probe q_localarr)
            if c.proc_frame is None:  # DEF FN LOCAL arrays unwitnessed
                raise ValueError(f"LOCAL DIM bracket outside a SUB body at {addr:#x}")
            disp = op[2] - 2
            l.local_dim_frame = DimFrame(
                base=disp,
                cells={2: ir.Lit(op[3]), 6: ir.Lit(img.ops[c.k + 1][3])},
                start=c.cur,
            )
            c.cur = None
            state.advance(4)  # type write, esize write, far_ref_bp, dim_begin
            continue
        if (
            kind == "far_ref_bp"
            and l.local_dim_frame is None
            and c.k + 1 < len(img.ops)
            and img.ops[c.k + 1][1] == "dim_begin"
        ):  # Mixed LOCAL frame: the runtime array's bracket opens directly;
            # unlike the sole-array shape above, no duplicate type/size writes
            # precede it (wild cleanup.exe/reformat.exe).
            frame = (
                c.proc_frame if c.proc_frame is not None else c.fn_frame
            )
            if frame is None or frame.locals is None:
                raise ValueError(f"LOCAL DIM bracket outside a LOCAL frame at {addr:#x}")
            disp = op[2]
            span = {disp + 2 * i for i in range(_LOCAL_ARR_WORDS)}
            if not span <= set(frame.locals):
                raise ValueError(f"LOCAL DIM descriptor exceeds frame at {addr:#x}")
            l.local_dim_frame = DimFrame(base=disp, start=c.cur)
            c.cur = None
            state.advance(2)
            continue
        if (
            kind == "far_ref_bp"
            and c.k + 1 < len(img.ops)
            and img.ops[c.k + 1][1] == "erase"
        ):  # ERASE of a BP-relative LOCAL DYNAMIC array (block DEF FN:
            # t1_fnlocalarrstr; wild cleanup.exe/reformat.exe).
            disp = op[2]
            if disp not in l.r_arrs:
                raise ValueError(f"ERASE of undimensioned LOCAL block at {addr:#x}")
            state.put(ir.Erase(l.r_arrs[disp]["name"]), c.cur)
            c.cur = None
            state.advance(2)
            continue
        if (
            kind == "mov_bp_imm"
            and l.local_dim_frame is not None
            and l.local_dim_frame.base
            <= op[2]
            < l.local_dim_frame.base + ARR_BLOCK
        ):  # LOCAL DYNAMIC array descriptor field write (type/size/bounds)
            l.local_dim_frame.cells[op[2] - l.local_dim_frame.base] = (
                ir.Lit(op[3])
            )
            state.advance()
            continue
        if (
            kind == "movm_ax_bp"
            and l.local_dim_frame is not None
            and l.local_dim_frame.base
            <= op[2]
            < l.local_dim_frame.base + ARR_BLOCK
        ):  # computed LOCAL DIM descriptor cell, e.g. an upper bound loaded
            # from another BP-relative INTEGER local (t1_fnlocalarrstr;
            # wild cleanup.exe/reformat.exe).
            if m.ax is None:
                raise ValueError(f"LOCAL DIM cell store without AX at {addr:#x}")
            l.local_dim_frame.cells[
                op[2] - l.local_dim_frame.base
            ] = m.ax
            m.ax = None
            state.advance()
            continue
        if kind == "far_ref_bp" and c.k + 1 < len(img.ops) and (
            img.ops[c.k + 1][1] == "dim_end"
        ):  # dim_end: finalize the LOCAL DYNAMIC array descriptor opened above
            disp = op[2]
            if l.local_dim_frame is None or l.local_dim_frame.base != disp:
                raise ValueError(f"unbalanced LOCAL DIM bracket at {addr:#x}")
            cells = l.local_dim_frame.cells
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
            if tb not in (0x00, 0x04, 0x0A):  # INTEGER / SINGLE / STRING
                raise ValueError(
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
                if l.option_base not in (None, lo.value):
                    raise ValueError("inconsistent OPTION BASE across DIMs")
                l.option_base = lo.value
            suffix = "%" if tb == 0x00 else ("$" if tb == 0x0A else "")
            name = (
                f"V{l.lay['n_static'] + len(l.lay['rt_blocks']) + l.n_local_arrs}"
                f"{suffix}"
            )
            l.n_local_arrs += 1
            rec = {
                "name": name,
                "rank": 1,
                "str": tb == 0x0A,
                "esz": expect_esz,
                "lo": [lo.value],
            }
            l.r_arrs[disp] = rec
            l.slot_info[disp] = rec
            bounds = (lo.value, hi) if expl else hi
            state.put(
                ir.Dim(name, (bounds,), dynamic=False),
                l.local_dim_frame.start,
            )
            # Fold the whole reserved template out of the SUB's plain scalar
            # LOCAL slots (private array bookkeeping, not user variables --
            # only 5 of its 30 reserved words are ever written, the rest is
            # dead padding in a fixed-size template used regardless of rank/
            # type, witnessed identical for both rank-1 and rank-2 probes)
            # and register the array's own name in the handle's place, so
            # `LOCAL <name>()` renders where `LOCAL A()` appeared in source.
            frame = (
                c.proc_frame if c.proc_frame is not None else c.fn_frame
            )
            if frame is None or not frame.locals:
                raise ValueError(f"LOCAL DIM without a LOCAL declaration at {addr:#x}")
            span = {disp + 2 * i for i in range(_LOCAL_ARR_WORDS)}
            if not span <= set(frame.locals):
                raise ValueError(f"LOCAL DIM descriptor exceeds frame at {addr:#x}")
            _drop_local_descriptor_initializers(state, frame, span, addr)
            frame.hidden_locals.update(
                disp + 2 * i for i in range(1, _LOCAL_ARR_WORDS)
            )
            frame.locals[disp] = f"{name}()"
            l.local_dim_frame = None
            c.cur = None
            state.advance(2)
            continue
        if kind == "proc_ret":
            assert c.proc_frame is not None  # proc_ret only closes an open SUB body
            state.flush_pending()
            _apply_exit_folds(
                out.stmts, out.addrs, c.exit_folds
            )  # EXIT SUB fold (Task 3.5), body-local
            c.exit_folds.clear()
            # Multi-line IF blocks inside the body, the same fold the top level
            # runs once every statement is in (see `_fold_if` below): a SUB body
            # is snapshotted here and never revisited by that pass, so it has to
            # happen now or its IfInlines stay inline and the else-skip Goto
            # survives as a spurious statement (probe t1_dblhooksub).
            i0 = state.frame_start(c.proc_frame.seq, c.proc_frame.idx)
            state.drain_folds(i0)  # the body's own IFs, before it is snapshotted
            with editing(out.stmts, "fold_proc_body"):
                out.stmts[i0:], out.addrs[i0:] = _fold_if(
                    out.stmts[i0:],
                    out.addrs[i0:],
                    targets=_jump_targets(out.stmts),
                    stmt_addr=out.stmt_addr,
                    block_ifs=c.block_if_addrs,
                )
            body = tuple(out.stmts[i0:])
            for st, ad in zip(body, out.addrs[i0:]):
                if ad is not None:  # keep body addrs: GOSUB targets a body
                    out.stmt_addr.claim(st, ad)  # line (t1_subgsb)
            with editing(out.stmts, "fold_proc_body"):
                del out.stmts[i0:], out.addrs[i0:]
            locs = c.proc_frame.locals
            _retire_for_temps(c.proc_frame, locs)
            for d in c.proc_frame.hidden_locals:
                if locs is not None:
                    locs.pop(d, None)  # var-STEP FOR temps (see above): never
            if locs:  # declared LOCALs, just deferred out of the dict
                # until every reference to them was resolved. The
                # zero-fill always runs right after proc_enter, regardless
                # of where LOCAL appears in source, so it's always the
                # body's first physical line (t1_local1)
                body = (ir.Local(tuple(locs.values())),) + body
            c.nsub += 1
            name = f"SUB{c.nsub}"
            c.proc_names[c.proc_frame.entry] = name
            # retf pop bytes = 4 x nargs, PLUS the LOCAL frame's own span: the
            # locals' stack space is caller-allocated too, so retf pops it
            # right along with the params (witnessed t1_local2)
            array_params = c.proc_frame.array_params
            if array_params:
                # Runtime vector D4 copies a rank-1 DESCRIPTOR (0x3C bytes) for
                # each whole-array parameter, rather than passing it as
                # ordinary four-byte by-ref slots -- and a signature may MIX
                # the two: `SUB One(X$(1), N%)` (t1_arrparmmix; TBWINDOW's
                # `Makevmenu(item$(1), liveitem$, itemcount, ...)` is the same
                # shape with nine scalars).
                fw = 2 * (c.proc_frame.frame_words or 0)
                scalar_bytes = op[2] - fw - 0x3C * len(array_params)
                if scalar_bytes < 0 or scalar_bytes % 4:
                    raise ValueError(
                        f"unsupported array-parameter frame at {addr:#x}"
                    )
                # Params fill the frame from bp+6 UPWARD in reverse source
                # order -- the last source param lands nearest bp+6, which is
                # exactly what the all-scalar branch's `6 + 4*(nparams-1-i)`
                # encodes. Each descriptor's own start offset is witnessed
                # (its `moves_bp` segment-word load keys array_params), so walk
                # the frame and let those offsets decide which slot is an array
                # and which a scalar, instead of assuming an order.
                slots, off = [], 6
                for _ in range(len(array_params) + scalar_bytes // 4):
                    rec = array_params.get(off)
                    if rec is None:
                        slots.append(_scalar_param_name(state, off))
                        off += 4
                    elif "name" in rec:
                        slots.append(f"{rec['name']}(1)")
                        off += 0x3C
                    else:  # descriptor never element-accessed: no type evidence
                        raise ValueError(
                            f"unsupported array-parameter frame at {addr:#x}"
                        )
                if off != 6 + op[2] - fw:  # every descriptor offset accounted
                    raise ValueError(  # for, and the frame exactly consumed
                        f"unsupported array-parameter frame at {addr:#x}"
                    )
                params = tuple(reversed(slots))
            else:
                nparams = (
                    op[2]
                    - 2
                    * (
                        len(locs or ())
                        if c.proc_frame.frame_words is None
                        else c.proc_frame.frame_words
                    )
                ) // 4
                params = tuple(
                    _scalar_param_name(state, off)
                    for off in (6 + 4 * (nparams - 1 - i) for i in range(nparams))
                )
            c.proc_params[c.proc_frame.entry] = params
            if c.fwd_inline_offs:
                # An argument forwarded to a SUB ... INLINE was spelled before
                # this frame's param types were settled (see handlers.control).
                # Re-point those unsuffixed placeholders at the declared
                # spelling, or the header and the body name two different
                # variables and rename.py letters them apart (t1_fwdinline).
                # The INLINE call can combine the forwarded formals with
                # expressions over their siblings (Openwin passes `col +
                # cols`, for example).  The assembly boundary requires the
                # whole scalar signature's concrete stack widths.  Normalize
                # unsuffixed numeric slots to INTEGER; retain independently
                # evidenced string, LONG, and DOUBLE spellings (tbd73's
                # DEFINT-authored Openwin; t1_fwdinline).
                fwd_bases = {
                    p.rstrip("%$&#")
                    for p in params
                    if p.startswith("P") and not p.endswith("(1)")
                }
                spell = {}
                for p in params:
                    if p.endswith("(1)"):
                        continue
                    base = p.rstrip("%$&#")
                    if base not in fwd_bases:
                        continue
                    want = p if p[-1:] in "$&#" else f"{base}%"
                    spell[p] = want
                    spell[base] = want  # staged arg_push_fwd placeholder
                params = tuple(spell.get(p, p) for p in params)
                body = tuple(
                    _respell_params(b, spell, out.stmt_addr) for b in body
                )
                c.fwd_inline_offs.clear()
            out.stmts.append(ir.SubDef(name, params, body))
            out.addrs.append(None)  # a SUB definition is never a jump target
            c.proc_frame = None
            c.cur = None
            state.advance()
            continue
        if handlers.calls(state, op, addr, kind):
            continue
        # --- DEF FN body & value-returning FN call ---
        if kind == "mov_bp_imm":  # [bp+n]=0 result-slot init in a DEF FN body:
            # numeric/block FNs zero [bp+0] AND [bp+2]; a single-line STRING
            # FN zeroes only [bp+2] (the descriptor's pointer word) -- so
            # only the [bp+0] init marks the multi-line form (t1_fnstr).
            frame = c.proc_frame if c.proc_frame is not None else c.fn_frame
            if (
                frame is not None and (frame.locals or {}).get(op[2]) is not None
            ):  # LOCAL int var = constant, e.g. a FOR init (q_locidx) -- same
                # shape whether the LOCAL lives in a SUB or a DEF FN body
                # (wild resume.exe: `LOCAL B% ... B% = 5` inside a DEF FN);
                # checked BEFORE the DEF-FN reserved-cell branch below since a
                # LOCAL can reuse a low bp offset the result slot doesn't use
                # (e.g. a zero-param FN's first LOCAL sits at bp+2).
                if c.cur is None:
                    c.cur = addr
                state.put(
                    ir.Assign(state.loc_local(op[2]), ir.Lit(op[3])), c.cur
                )
                c.cur = None
                state.advance()
                continue
            if c.fn_frame is not None:
                if op[2] == 0:
                    if c.fn_frame.block:
                        # A LITERAL result assignment -- `FNCurdisplay = 4`
                        # (wild tbd73.exe, TBW73.INC:314-357) -- NOT the
                        # prologue's result-slot init. Identical op, identical
                        # cell; only the POSITION separates them, since the
                        # prologue's own write is what sets `block` just below
                        # and a literal-zero result (`FNCurdisplay = 0`) makes
                        # the immediate useless as a discriminator.
                        #
                        # Every bp+0 literal store used to be swallowed as the
                        # marker, which silently DROPPED each `FNname =
                        # <literal>` from the body. That one omission is what
                        # made tbd73.exe's DEF FNCurdisplay lose all five of
                        # its result assignments -- taking its `%` suffix with
                        # them (the suffix rides the `int` flag set here, per
                        # t1_fnintcall's own gap 2) and leaving a jump target
                        # at the last one, 0xa637, with no statement to resolve
                        # to (`jump target 0xa637 is not a statement start`).
                        # Mirrors movm_ax_bp's bp+0 branch, the computed-result
                        # sibling of this literal one.
                        c.fn_frame.int_result = True  # a WORD store to bp+0:
                        # a SINGLE-valued FN stores its result via fstp instead
                        if c.cur is None:
                            c.cur = addr
                        state.put(ir.FnResult(ir.Lit(op[3])), c.cur)
                        c.cur = None
                    else:
                        c.fn_frame.block = True
                elif op[2] != 2:
                    raise ValueError(f"[bp+{op[2]}] init in DEF FN body at {addr:#x}")
            elif op[3] != 0:  # caller: literal-int FN-call arg staging (wild
                c.fn_args[op[2]] = ir.Lit(op[3])  # resume.exe, probe_d) --
                # a zero literal is indistinguishable from the zero-init of a
                # staged string-arg descriptor pointer (t1_fnstr) and stays
                # unsupported until a fixture disambiguates the two.
            state.advance()
            continue
        if kind == "fn_ret":  # close the open DEF FN body
            assert c.fn_frame is not None  # fn_ret only closes an open DEF FN body
            # The touched bp offsets ARE the param list, in ascending order:
            # an all-FP or all-string param list packs 4 bytes/param (P04,
            # P08, ...), an all-integer one packs 2 (P04, P06, ... -- wild
            # resume.exe, probe_d) -- no fixed stride can be assumed.
            params = tuple(
                f"P{off:02X}$"
                if off in c.fn_frame.str_offs
                else (
                    f"P{off:02X}%" if off in c.fn_frame.int_offs else f"P{off:02X}"
                )
                for off in sorted(c.fn_frame.param_offs)
            )
            c.nfn += 1
            name = f"FNFN{c.nfn}" + (
                "$" if c.fn_frame.str_result
                else "%" if c.fn_frame.int_result
                else ""
            )
            c.proc_names[c.fn_frame.entry] = name
            if c.fn_frame.block:  # multi-line DEF FN ... END DEF
                _apply_exit_folds(
                    out.stmts, out.addrs, c.exit_folds
                )  # EXIT DEF fold (body-local)
                c.exit_folds.clear()
                # Multi-line IF blocks inside the body -- the SAME fold
                # proc_ret runs for a SUB body, for the same reason: a DEF FN
                # body is snapshotted here and never revisited by the top-level
                # `_fold_if` pass, so without this its IfInlines stay inline.
                # Byte-significant, not cosmetic: a block IF compiles the
                # movax-FFFF materialization template and an inline one a bare
                # dispatch pair (t1_fnblockif). SUB bodies got this treatment
                # with t1_dblhooksub; DEF FN bodies were never given it.
                i0 = state.frame_start(c.fn_frame.seq, c.fn_frame.idx)
                state.drain_folds(i0)  # as proc_ret, before the snapshot
                with editing(out.stmts, "fold_proc_body"):
                    out.stmts[i0:], out.addrs[i0:] = _fold_if(
                        out.stmts[i0:],
                        out.addrs[i0:],
                        targets=_jump_targets(out.stmts),
                        stmt_addr=out.stmt_addr,
                        block_ifs=c.block_if_addrs,
                    )
                body = tuple(out.stmts[i0:])
                for st, ad in zip(body, out.addrs[i0:]):
                    if ad is not None:  # keep body addrs (as in the SUB fold)
                        out.stmt_addr.claim(st, ad)
                with editing(out.stmts, "fold_proc_body"):
                    del out.stmts[i0:], out.addrs[i0:]
                locs = c.fn_frame.locals
                _retire_for_temps(c.fn_frame, locs)
                for d in c.fn_frame.hidden_locals:
                    if locs is not None:
                        locs.pop(d, None)
                if locs:  # declared LOCALs (wild resume.exe), mirroring
                    body = (ir.Local(tuple(locs.values())),) + body  # proc_ret
                out.stmts.append(ir.DefFn(name, params, body, True))
            else:  # single-line DEF FN = expr
                expr = c.fn_frame.result
                if expr is None:  # no FSTP [bp+0]: result left on stack
                    expr = e.stack.pop()
                i0 = state.frame_start(c.fn_frame.seq, c.fn_frame.idx)
                state.drain_folds(i0)  # nothing survives the discard, but the
                # queue must not outlive the body it belongs to
                with editing(out.stmts, "fold_proc_body"):
                    del out.stmts[i0:], out.addrs[i0:]
                out.stmts.append(ir.DefFn(name, params, expr))
            out.addrs.append(None)  # a DEF FN definition is never a jump target
            c.fn_frame = None
            c.cur = None
            state.advance()
            continue
        if handlers.fp_bp(state, op, addr, kind):
            continue

        if handlers.cargs(state, op, addr, kind):
            continue
        # Literal-arg staging: glue ops carry no source.
        if kind == "mov_mem_sp":  # mov [cell],sp: remember the SP-save cell
            if c.cur is None:
                # A CALL whose argument-staging opens a loop body (the
                # backward branch's real re-entry point is THIS op, not
                # wherever the eventual CallStmt's put() happens to land
                # once far_call fires) needs its statement address anchored
                # here, mirroring the generic top-of-loop fallback below
                # that this early `continue` would otherwise skip (wild
                # morcalc.exe).
                c.cur = addr
            c.sp_save_cell = op[2]
            state.advance()
            continue
        if handlers.stack_ops(state, op, addr, kind):
            continue

        if handlers.bounds(state, op, addr, kind):
            continue
        if handlers.string_ops(state, op, addr, kind):
            continue
        if (
            kind == "movsi"
            and c.k + 1 < len(img.ops)
            and img.ops[c.k + 1][1] == "add_si_sp"
        ):
            # `mov si,off; add si,sp` selects one outgoing DEF-FN argument
            # slot.  `movm_*_temp` keys fn_args by this offset, so discarding
            # it makes successive arguments overwrite each other (tbd73's
            # `FNAttr(0, 0)` became `FNAttr(0)`).
            m.si = op[2]
            state.advance()
            continue
        if (
            kind == "movm_imm" and op[2] == c.sp_save_cell
        ):  # mov [cell],0: paired SP-save clear
            state.advance()
            continue
        if handlers.fp_math(state, op, addr, kind):
            continue
        if c.cur is None:
            c.cur = addr
        if (
            c.pend_arg is not None and kind == "far_spush"
        ):  # string by-ref param read
            c.proc_str_offs.add(c.pend_arg)
            e.sstack.append(ir.Var(f"P{c.pend_arg:02X}$"))
            c.pend_arg = None
            state.advance()
            continue
        if c.pend_arg is not None and kind == "far_strassign":
            # Far string assignment through a by-reference SUB parameter:
            # STRING$ (or another string expression) leaves the value on the
            # string stack, and LES SI,[BP+off] + far_strassign stores it into
            # the caller's descriptor (wild morcalc.exe).
            off = c.pend_arg
            c.proc_str_offs.add(off)
            state.put(ir.Assign(ir.Var(f"P{off:02X}$"), e.sstack.pop()), c.cur)
            c.pend_arg = None
            c.cur = None
            state.advance()
            continue
        if c.pend_arg is not None and kind.endswith(("_si", "_si32", "_si64")):
            argvar = ir.Var(f"P{c.pend_arg:02X}")
            base = kind[4:] if kind.startswith("far_") else kind  # strip far_ prefix
            if base == "fld_si":
                e.stack.append(argvar)
            elif base == "fstp_si":
                state.put(ir.Assign(argvar, e.stack.pop()), c.cur)
                c.cur = None
            elif base == "fold_si":
                e.stack.append(_orient(op[2], argvar, e.stack.pop()))
            elif base == "fold_n_si":  # mem is RIGHT operand
                top = e.stack.pop()
                if isinstance(top, ir.BinOp) and _PREC[top.op] < _PREC[op[2]]:
                    top = ir.Group(top)
                e.stack.append(ir.BinOp(op[2], top, argvar))
            elif base == "fcomp_si":
                e.pend_cmp = (argvar, e.stack.pop())
            elif base == "fild_si":  # by-ref int param onto the FP stack,
                argvar = ir.Var(f"P{c.pend_arg:02X}%")  # e.g. for PRINT
                c.proc_int_offs.add(c.pend_arg)  # (t1_byref1)
                e.stack.append(argvar)
            elif base == "cmpax_si":  # cmp ax, es:[si]: relational value vs a
                argvar = ir.Var(f"P{c.pend_arg:02X}%")  # by-ref INT param
                c.proc_int_offs.add(c.pend_arg)  # (t1_cmpfar)
                nx = img.ops[c.k + 1] if c.k + 1 < len(img.ops) else None
                j2 = img.ops[c.k + 2] if c.k + 2 < len(img.ops) else None
                if (
                    nx is not None
                    and nx[1] == "jcc"
                    and j2 is not None
                    and j2[1] == "jmp"
                    and nx[3] == j2[0] + 3
                ):
                    # IF form (`IF <param> < 1 THEN ... ELSE ...`, witnessed
                    # t1_cmpfarif / wild tbd73.exe's TBWINDOW `SUB Openwin`),
                    # as opposed to t1_cmpfar's relational-as-value form below.
                    # The compiler evaluates the SOURCE RHS into ax and compares
                    # the by-ref param as es:[si] memory, so flags are rhs-vs-lhs
                    # -- REVERSED, exactly like cmpax_m/cmpax_bp/the computed
                    # array-element cmpax_si, and their mirrored skip map applies
                    # unchanged. The param must stay on the LEFT: respelling it
                    # as `1 > <param>` is logically equal but puts the param in
                    # ax and recompiles to different bytes. Only "<" is
                    # witnessed; the other rows follow the same orientation
                    # derivation as the three sibling forms'.
                    skiprel = {
                        0x74: "<>", 0x75: "=", 0x7F: ">=",
                        0x7D: ">", 0x7C: "<=", 0x7E: "<",
                    }
                    if nx[2] not in skiprel:
                        raise ValueError(
                            f"by-ref cmpax_si IF jcc {nx[2]:02x} at {addr:#x}"
                        )
                    # A tail IF closing the procedure skips to the epilogue,
                    # which is not a statement (see open_tail_if). Negating
                    # `skiprel` recovers the source polarity while KEEPING the
                    # param on the left, which the orientation note above
                    # requires (wild tbd73.exe, TBW73.INC:634 closes
                    # `SUB Drawlist` with exactly this compare form).
                    if state.open_tail_if(
                        j2[2],
                        ir.RelOp(_NEGATE_REL[skiprel[nx[2]]], argvar, m.ax),
                    ):
                        m.ax = None
                        c.pend_arg = None
                        state.advance(3)
                        continue
                    state.put(
                        ir.IfGoto(
                            ir.RelOp(skiprel[nx[2]], argvar, m.ax),
                            ("addr", j2[2]),
                        ),
                        c.cur,
                    )
                    m.ax = None
                    c.cur = None
                    c.pend_arg = None
                    state.advance(3)
                    continue
                e.pend_icmp = (argvar, m.ax)
                m.ax = None
            elif base == "addax_si":  # add ax, es:[si]: arithmetic fold of a
                argvar = ir.Var(f"P{c.pend_arg:02X}%")  # by-ref INT param
                c.proc_int_offs.add(c.pend_arg)  # (t1_local2)
                nx = img.ops[c.k + 1] if c.k + 1 < len(img.ops) else None
                expr = ir.BinOp("+", argvar, _rgrp("+", m.ax))
                if isinstance(m.ax, ir.Neg) and nx is not None and nx[1] == "cwd":
                    # `NEG AX; ADD AX,ES:[SI]; CWD; IDIV` is TB's source
                    # `param - expr` template.  Keep the machine-derived
                    # syntax choice in IR: t1_iftaillast's `...; ADD` sibling
                    # remains an actual addition of a negative.
                    m.ax = ir.Template("subtraction", expr)
                else:
                    m.ax = expr
            elif base == "subax_si":  # sub ax, es:[si]: subtractive fold of a
                argvar = ir.Var(f"P{c.pend_arg:02X}%")  # by-ref INT param,
                c.proc_int_offs.add(c.pend_arg)  # mem on the right
                m.ax = ir.BinOp("-", m.ax, _rgrp("-", argvar))  # like subax_m
            elif base == "andax_si":  # and ax, es:[si]: bitwise fold of a
                argvar = ir.Var(f"P{c.pend_arg:02X}%")  # by-ref INT param
                c.proc_int_offs.add(c.pend_arg)  # (t1_byref1)
                m.ax = ir.BinOp("AND", argvar, _rgrp("AND", m.ax))
            elif base == "orax_si":  # or ax, es:[si]: bitwise OR fold of a
                argvar = ir.Var(f"P{c.pend_arg:02X}%")  # by-ref INT param
                c.proc_int_offs.add(c.pend_arg)  # (wild pwinst.exe)
                m.ax = ir.BinOp("OR", argvar, _rgrp("OR", m.ax))
            elif base == "imulax_si":  # imul word es:[si]: multiplicative
                argvar = ir.Var(f"P{c.pend_arg:02X}%")  # fold of a by-ref
                c.proc_int_offs.add(c.pend_arg)  # INT param (q_byref_imul)
                m.ax = ir.BinOp("*", argvar, _rgrp("*", m.ax))
            elif base == "movax_si":  # mov ax, es:[si]: plain read of a
                argvar = ir.Var(f"P{c.pend_arg:02X}%")  # by-ref INT param,
                c.proc_int_offs.add(c.pend_arg)  # e.g. an expression's
                m.ax = argvar  # first term (t1_byref1)
            elif base == "movm_ax_si":  # mov es:[si], ax: write ax into a
                argvar = ir.Var(f"P{c.pend_arg:02X}%")  # by-ref INT param
                c.proc_int_offs.add(c.pend_arg)  # (t1_byref1)
                state.put(ir.Assign(argvar, m.ax), c.cur)
                m.ax = None
                c.cur = None
            elif base == "addm_ax_si":  # add es:[si], ax: compound-store add
                argvar = ir.Var(f"P{c.pend_arg:02X}%")  # into a by-ref INT
                c.proc_int_offs.add(c.pend_arg)  # param (q_fwd)
                state.put(
                    ir.Assign(argvar, ir.BinOp("+", argvar, _rgrp("+", m.ax))),
                    c.cur,
                )
                m.ax = None
                c.cur = None
            elif base == "subm_ax_si":  # sub es:[si], ax: compound-store
                argvar = ir.Var(f"P{c.pend_arg:02X}%")  # subtract into a
                c.proc_int_offs.add(c.pend_arg)  # by-ref INT param
                state.put(
                    ir.Assign(argvar, ir.BinOp("-", argvar, _rgrp("-", m.ax))),
                    c.cur,
                )
                m.ax = None
                c.cur = None
            elif base == "movm_imm_si":  # mov word es:[si], imm16: write a
                argvar = ir.Var(f"P{c.pend_arg:02X}%")  # constant into a
                c.proc_int_offs.add(c.pend_arg)  # by-ref INT param
                state.put(ir.Assign(argvar, ir.Lit(op[2])), c.cur)  # (t1_byref1)
                c.cur = None
            elif base == "inc_si":  # inc es:[si]: FOR-NEXT increment of a
                # by-ref int param used directly as the loop var -- implicit
                # in BASIC; consume silently, same as inc_m/inc_bp (wild
                # bmaster.exe/ifi.exe). Outside a FOR, `X% = X% + 1` instead
                # compiles to far_addm_ax_si (t1_local2) -- like the LOCAL
                # case, a bare INCR statement is NOT byte-identical to that
                # spelling for a by-ref param, so it decodes as its own
                # `ir.Incr` node (wild bmaster.exe/ifi.exe, probe
                # q_byrefincr).
                if c.fors and c.fors[-1].v == c.pend_arg:
                    pass
                else:
                    argvar = ir.Var(f"P{c.pend_arg:02X}%")
                    c.proc_int_offs.add(c.pend_arg)
                    state.put(ir.Incr(argvar), c.cur)
                    c.cur = None
            elif base == "dec_si":  # dec es:[si]: FOR-NEXT STEP -1 decrement
                # of a by-ref int param used as the loop var -- the
                # descending sibling of inc_si, same NEXT-side step patch-up
                # as dec_m/dec_bp (the header folded a provisional Lit(1)
                # step before this evidence was available) -- or, outside a
                # FOR, a bare `DECR <by-ref param>` statement, the exact
                # mirror of inc_si's own non-FOR leg: by-ref `X% = X% - 1`
                # compiles to far_subm_ax_si instead, so DECR is not
                # byte-identical to that spelling and needs its own ir.Decr
                # node (wild bmaster.exe/ifi.exe for the FOR leg;
                # t1_byrefdecr / wild tbd73.exe's TBWINDOW `SUB Makevmenu`,
                # `CASE CHR$(72) : DECR curntpos`, for the bare leg).
                if c.fors and c.fors[-1].v == c.pend_arg:
                    f = c.fors[-1]
                    old = out.stmts[f.idx]
                    out.stmts[f.idx] = ir.For(
                        old.var, old.init, old.limit, ir.Lit(-1)
                    )
                    f.step = -1
                else:
                    argvar = ir.Var(f"P{c.pend_arg:02X}%")
                    c.proc_int_offs.add(c.pend_arg)
                    state.put(ir.Decr(argvar), c.cur)
                    c.cur = None
            elif base == "fild_si32":  # by-ref LONG param onto the FP stack:
                argvar = ir.Var(f"P{c.pend_arg:02X}&")  # the m32 sibling of
                c.proc_long_offs.add(c.pend_arg)  # fild_si's m16 read
                e.stack.append(argvar)  # (wild bmaster.exe/ifi.exe,
                # probe q_longread)
            elif base == "fstp_si32":  # FP stack top -> a by-ref LONG param:
                argvar = ir.Var(f"P{c.pend_arg:02X}&")  # the m32 sibling
                c.proc_long_offs.add(c.pend_arg)  # of fstp_si's write
                state.put(ir.Assign(argvar, e.stack.pop()), c.cur)
                c.cur = None  # (wild bmaster.exe/ifi.exe, probe q_longwrite)
            elif base == "icomp_si32":  # by-ref LONG param vs FP-stack value
                argvar = ir.Var(f"P{c.pend_arg:02X}&")  # (mixed-type
                c.proc_long_offs.add(c.pend_arg)  # IF/loop test, the
                e.pend_cmp = (argvar, e.stack.pop())  # far/by-ref
                # sibling of the computed-array-element icomp_si32 (wild
                # bmaster.exe/ifi.exe, probe q_longcmp)
                e.pend_cmp_str = False  # replace any materialized string
                # flags a directly-preceding term left set (an AND-group's
                # own first term, no intervening consumer -- wild
                # bmaster.exe's second `(... AND ...) OR (LONG AND string)`
                # group, probe q_orofands2)
            elif base == "fld_si64":  # by-ref DOUBLE param onto the FP stack:
                argvar = ir.Var(f"P{c.pend_arg:02X}#")  # the m64 sibling
                c.proc_dbl_offs.add(c.pend_arg)  # of fld_si's m16
                e.stack.append(argvar)  # read (wild bmaster.exe/ifi.exe,
                # probe q_dblread)
            elif base == "fstp_si64":  # FP stack top -> a by-ref DOUBLE param:
                argvar = ir.Var(f"P{c.pend_arg:02X}#")  # the m64 sibling
                c.proc_dbl_offs.add(c.pend_arg)  # of fstp_si's write
                state.put(ir.Assign(argvar, e.stack.pop()), c.cur)
                c.cur = None  # (wild bmaster.exe/ifi.exe, probe q_dblwrite)
            elif base == "fcomp_si64":  # by-ref DOUBLE param vs FP-stack value
                argvar = ir.Var(f"P{c.pend_arg:02X}#")  # (IF/loop test,
                c.proc_dbl_offs.add(c.pend_arg)  # far/by-ref sibling
                e.pend_cmp = (argvar, e.stack.pop())  # of the
                # computed-array-element fcomp_si64 (wild bmaster.exe/
                # ifi.exe, probe q_dblcmp)
                e.pend_cmp_str = False  # replace any materialized string
                # flags a directly-preceding term left set (same AND-group
                # hygiene as icomp_si32 above)
            else:
                raise ValueError(f"unhandled by-ref param op {kind} at {addr:#x}")
            c.pend_arg = None
            state.advance()
            continue
        if (
            kind in ("testw", "testw_bp")
            and c.fors
            and addr == c.fors[-1].test
        ):
            state.seek(_lift_next(
                img.ops,
                c.k,
                c.fors,
                out.stmts,
                out.addrs,
                c.exit_folds,
            ))
            c.cur = None
            continue
        if (
            kind == "orax_self"
            and c.fors
            and addr == c.fors[-1].test
            and c.fors[-1].var_step
        ):
            state.seek(_lift_var_step_next(
                img.ops, c.k, c.fors, out.stmts, out.addrs
            ))
            c.cur = None
            continue
        if (
            kind == "movax_m"
            and c.fors
            and addr == c.fors[-1].test
            and c.k + 2 < len(img.ops)
            and img.ops[c.k + 1][1] == "cmpm_ax"
            and img.ops[c.k + 1][2] == c.fors[-1].v
        ):
            # Variable-limit integer NEXT: `mov ax,[limit]; cmp [I%],ax; jle body`
            # (t1_fori; inc_m was consumed, step is always 1 until a NEXT-
            # side dec_m/dec_bp patch proves STEP -1, mirroring the
            # literal-limit cmp_mi8 case's JGE test then -- wild
            # morcalc.exe). A body beyond short-jump range uses the inverse
            # condition + JMP instead (same indirect form cmp_mi8 already
            # handles, wild pwinst.exe).
            f = c.fors[-1]
            jcc = img.ops[c.k + 2]
            wantcc = (0x7D,) if f.step < 0 else (0x7E, 0x76)
            invcc = (0x7C,) if f.step < 0 else (0x7F, 0x77)
            direct = jcc[1] == "jcc" and jcc[2] in wantcc and jcc[3] == f.body
            indirect = (
                c.k + 3 < len(img.ops)
                and jcc[1] == "jcc"
                and jcc[2] in invcc
                and img.ops[c.k + 3][1] == "jmp"
                and img.ops[c.k + 3][2] == f.body
                and jcc[3] == img.ops[c.k + 3][0] + 3
            )
            if not (direct or indirect):
                raise ValueError(f"int NEXT (var limit): expected JLE to body at {addr:#x}")
            state.put(ir.NextStmt(state.loc(f.v)), c.cur)
            c.fors.pop()
            c.cur = None
            state.advance(4 if indirect else 3)
            continue
        if (
            kind == "movax_bp"
            and c.fors
            and addr == c.fors[-1].test
            and c.k + 2 < len(img.ops)
            and img.ops[c.k + 1][1] == "cmpm_ax_bp"
            and img.ops[c.k + 1][2] == c.fors[-1].v
        ):
            # Variable-limit integer NEXT, LOCAL loop var: the bp-relative
            # mirror of the movax_m/cmpm_ax case just above (wild
            # bmaster.exe/ifi.exe, probe q_locforvarlim). A body beyond
            # short-jump range takes the inverse condition + JMP, the same
            # indirect form that case already handles -- witnessed here by
            # t1_locforlong / wild tbd73.exe's TBWINDOW `SUB Makevmenu`
            # (`FOR mloop = 1 TO itemcount` around a body of CALL Sprint /
            # Scolor statements, well past 127 bytes).
            f = c.fors[-1]
            jcc = img.ops[c.k + 2]
            direct = (
                jcc[1] == "jcc" and jcc[2] in (0x7E, 0x76) and jcc[3] == f.body
            )
            indirect = (
                c.k + 3 < len(img.ops)
                and jcc[1] == "jcc"
                and jcc[2] in (0x7F, 0x77)
                and img.ops[c.k + 3][1] == "jmp"
                and img.ops[c.k + 3][2] == f.body
                and jcc[3] == img.ops[c.k + 3][0] + 3
            )
            if not (direct or indirect):
                raise ValueError(f"int NEXT (var limit): expected JLE to body at {addr:#x}")
            state.put(ir.NextStmt(state.loc_local(f.v)), c.cur)
            c.fors.pop()
            c.cur = None
            state.advance(4 if indirect else 3)
            continue
        if (
            kind == "movax_bp"
            and c.fors
            and addr == c.fors[-1].test
            and c.k + 3 < len(img.ops)
            and img.ops[c.k + 1][1] == "arg_ref"
            and img.ops[c.k + 1][2] == c.fors[-1].v
            and img.ops[c.k + 2][1] == "far_cmpm_ax_si"
        ):
            # Variable-limit integer NEXT, BY-REF PARAM loop var: the
            # ES:[SI] mirror of the two cases just above -- the loop var
            # is itself a by-ref int parameter, addressed fresh via its own
            # arg_ref/les at every test (wild bmaster.exe/ifi.exe, probe
            # q_byrefforvar).
            f = c.fors[-1]
            jcc = img.ops[c.k + 3]
            if jcc[1] != "jcc" or jcc[2] not in (0x7E, 0x76) or jcc[3] != f.body:
                raise ValueError(f"int NEXT (var limit): expected JLE to body at {addr:#x}")
            state.put(ir.NextStmt(ir.Var(f"P{f.v:02X}%")), c.cur)
            c.fors.pop()
            c.cur = None
            state.advance(4)
            continue
        if (
            kind in ("cmp_mi8", "cmp_mi16", "cmp_bpi8")
            and c.fors
            and addr == c.fors[-1].test
        ):
            # Integer FOR-test guard: the cmp at the open FOR's test address is the
            # integer NEXT template (`inc_m`/`addm_i8` was consumed; cmp_mi16 when
            # the limit doesn't fit a signed imm8, q_forbig). Ascending steps (the
            # default, and any literal step >= 0) test JLE/JBE; descending literal
            # steps (addm_i8 with a negative imm8) test JGE, its signed mirror
            # (q_forstepneg).
            f = c.fors[-1]
            if op[2] != f.v:
                raise ValueError(f"int NEXT: cmp disp mismatch at {addr:#x}")
            wantcc = (0x7D,) if f.step < 0 else (0x7E, 0x76)
            direct = (
                c.k + 1 < len(img.ops)
                and img.ops[c.k + 1][1] == "jcc"
                and img.ops[c.k + 1][2] in wantcc
                and img.ops[c.k + 1][3] == f.body
            )
            # A body beyond short-jump range uses the inverse short condition
            # over a near JMP back to the body: JG/JA skip; JMP body. Wild
            # number.exe witnesses the ascending signed JG form.
            invcc = (0x7C,) if f.step < 0 else (0x7F, 0x77)
            indirect = (
                c.k + 2 < len(img.ops)
                and img.ops[c.k + 1][1] == "jcc"
                and img.ops[c.k + 1][2] in invcc
                and img.ops[c.k + 2][1] == "jmp"
                and img.ops[c.k + 2][2] == f.body
                and img.ops[c.k + 1][3]
                == img.ops[c.k + 2][0] + 3
            )
            if not (direct or indirect):
                raise ValueError(f"int NEXT: expected JLE/JBE/JGE to body at {addr:#x}")
            state.put(
                ir.NextStmt(
                    state.loc_local(f.v) if kind == "cmp_bpi8" else state.loc(f.v)
                ),
                c.cur,
            )
            c.fors.pop()
            c.cur = None
            state.advance(3 if indirect else 2)
            continue
        if handlers.int_alu(state, op, addr, kind):
            continue
        if kind == "epilogue":
            return _finalize(state, addr)

        if kind == "end":
            state.put(ir.End(), c.cur)
            c.cur = None
            state.advance()
            continue
        if handlers.movax_family(state, op, addr, kind):
            continue

        if kind == "movax_m":  # int var load (right operand first)
            if op[2] == 0x74:  # runtime cells, not user slots:
                m.ax = ir.Err()
            elif op[2] == 0x72:  # ERR = [0074], ERL = [0072]
                m.ax = ir.Erl()
            else:
                try:
                    m.ax = state.loc(op[2])
                except ValueError:
                    # Pooled int-literal operand of a divide/idiv chain
                    # (`POOL_LIT \ 2`, wild rsltest.exe) -- same pool-
                    # literal fallback addax_m/subax_m/imul_m already have.
                    if op[2] < l.lay["pool_base"] - 4:
                        raise
                    m.ax = state.pool_lit(op[2])
            state.advance()
            continue
        if handlers.int_bitwise_m(state, op, addr, kind):
            continue

        if kind == "cwd":  # sign-extend ahead of idiv: lift no-op
            state.advance()
            continue
        if handlers.int_bitwise_bx(state, op, addr, kind):
            continue

        if (
            kind == "movdx"
            and c.k + 2 < len(img.ops)
            and img.ops[c.k + 1][1] == "movesdx"
            and img.ops[c.k + 2][1] == "fn_bound"
        ):  # UBOUND/LBOUND(arr(dim)): slot in
            rec = l.slot_info.get(
                getattr(m.bx, "value", None)
            )  # bx, dim in ax, es = seg
            if rec is None:
                raise ValueError(f"UBOUND/LBOUND array slot unknown at {addr:#x}")
            m.ax = ir.Call(
                img.ops[c.k + 2][2], (ir.ArrayRef(rec["name"], (m.ax,)),)
            )
            m.bx = None
            state.advance(3)
            continue
        if kind == "movsi" and (_bj := _blit_at(img.ops, c.k)) is not None:
            rec = l.slot_info.get(op[2])  # (es:)si -> array slot record
            if rec is None:
                raise ValueError(
                    f"GET/PUT blit array slot {op[2]:#06x} unknown at {addr:#x}"
                )
            gp = img.ops[_bj]
            if gp[1] == "get_gfx":
                if gp[2] != 0:
                    raise ValueError(
                        f"GET blit trail byte {gp[2]:02x} at {addr:#x} (unsupported)"
                    )
                y2 = e.stack.pop()
                x2 = e.stack.pop()
                y1 = e.stack.pop()
                x1 = e.stack.pop()
                state.put(ir.GetGfx(x1, y1, x2, y2, rec["name"]), c.cur)
            else:
                if gp[2] not in _PUT_ACTIONS:
                    raise ValueError(
                        f"PUT blit action {gp[2]:02x} at {addr:#x} (unsupported)"
                    )
                y = e.stack.pop()
                x = e.stack.pop()
                state.put(ir.PutGfx(x, y, rec["name"], _PUT_ACTIONS[gp[2]]), c.cur)
            c.cur = None
            state.seek(_bj + 1)
            continue
        if handlers.timing(state, op, addr, kind):
            continue
        if (
            kind == "movsi"
            and c.k + 3 < len(img.ops)
            and img.ops[c.k + 1][1] == "movdx"
            and img.ops[c.k + 2][1] == "movesdx"
            and img.ops[c.k + 3][1]
            in ("dim_begin", "dim_end", "erase", "erase_static")
        ):
            block = op[2]  # runtime-DIM bracket
            if img.ops[c.k + 3][1] == "dim_begin":
                l.dim_frame = DimFrame(base=block, start=c.cur)
            elif img.ops[c.k + 3][1] == "erase":  # ERASE
                rec = l.r_arrs.get(block)
                if rec is not None:
                    state.put(ir.Erase(rec["name"]), c.cur)
                elif block in l.lay["rt_blocks"]:
                    # ERASE reached BEFORE the array's own DIM in address order
                    # -- ordinary in a re-DIM loop whose ERASE sits on an
                    # earlier line, and in SUB bodies, which the compiler emits
                    # ahead of the main code that DIMs (probe t1_erasepre; wild
                    # rs.exe). The slot is a known runtime block either way, so
                    # name it off the grid exactly as the DIM handler below
                    # does, rather than demand the DIM have been seen first.
                    tb = exe[l.ds + block + 2]
                    suffix = (
                        "$" if tb == 0x0A
                        else "%" if tb == 0x00
                        else "#" if tb == 0x06
                        else "&" if tb == 0x02
                        else ""
                    )
                    idx = l.lay["n_static"] + l.lay["rt_blocks"].index(block)
                    state.put(ir.Erase(f"V{idx}{suffix}"), c.cur)
                else:
                    raise ValueError(f"ERASE of undimensioned block at {addr:#x}")
            elif img.ops[c.k + 3][1] == "erase_static":
                # ERASE of a STATIC array: the runtime routine differs (it
                # re-initializes in place rather than freeing a heap block) but
                # the source spelling is the same, and the compiler picks the
                # vector back from the array's own DIM (probe t1_erasestatic).
                # The movsi target is the array's SLOT RECORD, so look it up in
                # the slot registry -- exactly as the whole-array CALL argument
                # path (`arg_push_array`) does with the same operand. This used
                # to re-derive an index positionally,
                # `divmod(block - var_base, ARR_BLOCK)`, which assumes every
                # slot record sits at a plain grid stride from var_base and so
                # broke for a static array whose record does not (wild
                # tbd73.exe's `SUB Showfile`: `DIM recarr$(5000)` with a
                # constant bound is a compile-time static -- the SUB body has
                # no dim_begin at all -- and `ERASE recarr$` at TBD73.BAS:409
                # raised `ERASE of unknown static slot`, while the
                # `CALL Makelmenu(recarr$(), ...)` twelve lines earlier
                # resolved the very same slot fine through the registry).
                a = l.slot_info.get(block)
                if a is None or a.get("rank", 0) < 1:
                    raise ValueError(f"ERASE of unknown static slot at {addr:#x}")
                state.put(ir.Erase(a["name"]), c.cur)
            else:
                if l.dim_frame is None or l.dim_frame.base != block:
                    raise ValueError(f"unbalanced DIM bracket at {addr:#x}")
                cells = l.dim_frame.cells
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
                        l.option_base not in (None, *base_vals)
                        or len(base_vals) != 1
                    ):
                        raise ValueError("inconsistent OPTION BASE across DIMs")
                    l.option_base = base_vals.pop()
                # Runtime slots carry their element type at file time:
                # 0A = string-descriptor elements, 06 = double (witnessed
                # t1_dblarr), so the name is typed from birth.
                tb = exe[l.ds + block + 2]
                is_str = tb == 0x0A
                suffix = "$" if is_str else "%" if tb == 0x00 else "#" if tb == 0x06 else "&" if tb == 0x02 else ""
                name = f"V{l.lay['n_static'] + l.lay['rt_blocks'].index(block)}{suffix}"
                if not all(isinstance(v, ir.Lit) for v in lows):
                    raise ValueError(
                        f"non-literal DIM lower bound at {addr:#x}: {lows}"
                    )
                l.r_arrs[block] = {
                    "name": name,
                    "rank": rank,
                    "str": is_str,
                    "esz": 8 if tb == 0x06 else 4 if tb in (0x02, 0x04, 0x0A) else 2,
                    "lo": [v.value for v in lows],
                }
                l.slot_info[block] = l.r_arrs[block]
                bounds = tuple(
                    (lo.value, u) if expl[d] else u
                    for d, (lo, u) in enumerate(zip(lows, ups))
                )
                if (
                    l.prev_dim_end is not None
                    and l.prev_dim_end + 3 not in out.commits
                    and isinstance(out.stmts[-1], ir.Dim)
                ):
                    prev = out.stmts[-1]  # no commit after the previous
                    with editing(out.stmts, "dim_declaration"):
                        state.patch(
                            -1,
                            ir.Dim(
                                prev.name,
                                prev.bounds,  # allocate: same
                                prev.also + ((name, bounds),),
                                prev.dynamic,
                            ),
                        )  # comma list
                else:
                    state.put(
                        ir.Dim(
                            name,
                            bounds,
                            # A COMMON'd array is in the band because COMMON put
                            # it there, not because DIM DYNAMIC did: it declares
                            # with a plain DIM, and spelling DYNAMIC instead
                            # compiles two bytes differently (probe
                            # t1_commonarr, verified against the oracle).
                            dynamic=block not in l.lay.get("common_arrs", ())
                            and all(
                                isinstance(v, int)
                                or isinstance(v, ir.Lit)
                                or (
                                    isinstance(v, tuple)
                                    and isinstance(v[1], (int, ir.Lit))
                                )
                                for v in bounds
                            ),
                        ),
                        l.dim_frame.start,
                    )
                l.prev_dim_end = img.ops[c.k + 3][0]
                l.dim_frame = None
            c.cur = None
            state.advance(4)
            continue
        if (
            kind == "movsi"
            and e.pend_field is not None
            and c.k + 3 < len(img.ops)
            and img.ops[c.k + 1][1] == "movdx"
            and img.ops[c.k + 2][1] == "movesdx"
            and img.ops[c.k + 3][1] == "field_as"
        ):
            # FIELD's AS-target: the width expression (a bare literal or a
            # computed one, wild hebrew.exe) already accumulated generically
            # into m.ax via the ordinary per-op dispatch above -- this
            # just closes out one FIELD entry and leaves pend_field open for
            # a possible next entry; flush_pending emits the ir.Field once
            # the next real statement starts (or EOF), same lazy-close
            # convention as the other open chains (READ/INPUT#/PRINT).
            if m.ax is None:
                raise ValueError(f"FIELD width missing at {addr:#x}")
            e.pend_field["fields"].append((m.ax, state.loc(op[2])))
            m.ax = None
            state.advance(4)
            continue
        if (
            kind == "movsi"
            and op[2] in l.lay["scalars"]
            and c.k + 3 < len(img.ops)
            and img.ops[c.k + 1][1] == "movdx"
            and img.ops[c.k + 2][1] == "movesdx"
            and img.ops[c.k + 3][1] == "str2num"
        ):
            # Reading a FIELD-buffer string variable as a value (e.g.
            # `X& = CVL(V$)` where V$ was FIELD'd): the same movsi/movdx/
            # movesdx far-pointer reconstruction as FIELD's own AS-target
            # (same disp witnessed in all three wild hits), just used to
            # PUSH the variable instead of naming an assignment target.
            # Confirmed the disp is an ordinary already-tracked string
            # scalar in all three (hebrew.exe/morcalc.exe/photo.exe) --
            # movdx/movesdx don't change WHICH variable this is.
            e.sstack.append(state.loc(op[2]))
            state.advance(3)
            continue
        if (
            kind in ("movm_imm", "movm_ax")
            and l.dim_frame is not None
            and l.dim_frame.base <= op[2] < l.dim_frame.base + ARR_BLOCK
        ):
            val = ir.Lit(op[3]) if kind == "movm_imm" else m.ax
            l.dim_frame.cells[op[2] - l.dim_frame.base] = val
            if kind == "movm_ax":
                m.ax = None
            state.advance()
            continue
        if kind == "movm_imm" and op[2] < VAR_BASE:  # system cell store
            if op[2] == 0x60:  # file number for OPEN / PRINT#
                state.flush_pending()  # statement boundary
                e.pend_fnum = op[3]
            elif op[2] in (
                0x88,
                0x94,
                0xA0,
                0xAC,  # COLOR fg/bg / VIEW coord cells
                0xB8,
                0xC4,
            ):  # VIEW color/border cells
                e.color_cells[op[2]] = ir.Lit(op[3])
            elif op[2] in (0x8A, 0x96, 0xA2, 0xAE, 0xBA, 0xC6):
                # Same COLOR/VIEW cell family, uniformly +2 from the above --
                # a runtime-revision-skewed table shift (RR-COLORCELL-SHIFT):
                # no oracle probe (SCREEN mode/switch/page variants, COLOR
                # with/without KEY OFF or DEF SEG) ever produced this
                # offset, only wild bill.exe/color.exe, but all 3 cells
                # witnessed there (fg/bg/border) shift by the same +2 and
                # the semantics are otherwise identical, so it normalizes to
                # the canonical cell with no effect on emitted source.
                e.color_cells[op[2] - 2] = ir.Lit(op[3])
            elif op[2] == 0x1C:  # TB 1.0 DEF SEG = n: inline imm
                state.put(
                    ir.DefSeg(ir.Lit(op[3])), c.cur
                )  # store (1.1 uses EC sub 0x26)
                c.cur = None
            elif op[2] == 0x2E:  # short-string scratch cell: a compile-time
                e.pend_shortstr = op[3]  # -known 1-char literal packed
                # (char<<8 | len=1), staged for the `shortstr` op that
                # follows (OPEN ... FOR mode AS #n; wild nvginst.exe)
            elif op[2] == 0x78:  # DATA read pointer: RESTORE [line]
                imm = op[3]  # 0 = bare RESTORE; N = RESTORE <line>
                if imm == 0:
                    state.put(ir.Restore(None), c.cur)
                elif imm < 0 or imm % 2:
                    raise ValueError(f"bad RESTORE pointer {imm} at {addr:#x}")
                else:
                    state.put(
                        ir.Restore(imm // 2), c.cur
                    )  # raw item index; resolved at epilogue
                c.cur = None
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
                state.put(ir.Assign(var, ir.Lit(op[3])), c.cur)
                c.cur = None
            state.advance()
            continue
        if kind == "movm_ax" and op[2] in (0x88, 0x94, 0xA0, 0xAC):
            e.color_cells[op[2]] = m.ax  # VIEW coord cell (ax leg)
            m.ax = None
            state.advance()
            continue
        if kind == "movm_ax" and op[2] in (0x8A, 0x96, 0xA2, 0xAE):
            e.color_cells[op[2] - 2] = m.ax  # RR-COLORCELL-SHIFT, see above
            m.ax = None
            state.advance()
            continue
        if kind == "movm_ax" and op[2] == 0x60:  # file number for INPUT#
            if not isinstance(m.ax, ir.Lit):
                raise ValueError(f"non-literal file number at {addr:#x}")
            state.flush_pending()  # statement boundary
            e.pend_fnum = m.ax.value
            m.ax = None
            state.advance()
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
                exe, l.dsd, l.lay, op[3]
            ):
                val = ir.Call("VARPTR", (v,))
            state.put(ir.Assign(state.loc(op[2]), val), c.cur)
            c.cur = None
            state.advance()
            continue
        if kind == "movm_ax":  # int var = ax expression
            state.put(ir.Assign(state.loc(op[2]), m.ax), c.cur)
            m.ax = None
            c.cur = None
            state.advance()
            continue
        if kind == "addm_ax":  # int var = var + ax expression, e.g.
            var = state.loc(op[2])  # `X% = X% + 3` (no INCR fast path since the
            state.put(  # RHS isn't a bare literal-1; disp16 sibling of
                ir.Assign(var, ir.BinOp("+", var, _rgrp("+", m.ax))),
                c.cur,  # addm_ax_bp, witnessed q_addimm)
            )
            m.ax = None
            c.cur = None
            state.advance()
            continue
        if kind == "subm_ax":  # int var = var - ax expression, e.g.
            var = state.loc(op[2])  # `X% = X% - <expr>` (subtract sibling
            state.put(  # of addm_ax; wild number.exe)
                ir.Assign(var, ir.BinOp("-", var, _rgrp("-", m.ax))),
                c.cur,
            )
            m.ax = None
            c.cur = None
            state.advance()
            continue
        if kind == "movm_ax_bp":  # LOCAL int var = ax expression, OR --
            # bp+0 inside an open DEF FN body -- the block-form FN's own
            # integer result store, mirroring fstp_bp's float-result special
            # case (bp+0 is the frame-link word in a SUB, never a real LOCAL,
            # so this can only mean the FN result there; wild resume.exe).
            if c.fn_frame is not None and op[2] == 0:
                c.fn_frame.int_result = True  # integer-typed result
                if c.fn_frame.block:
                    state.put(ir.FnResult(m.ax), c.cur)
                    c.cur = None
                else:
                    c.fn_frame.result = m.ax
                m.ax = None
                state.advance()
                continue
            if c.fn_frame is None and c.proc_frame is None:
                # caller: computed (or ax-routed literal) int FN-call arg
                # staging -- the ax-register sibling of mov_bp_imm's literal
                # form above (wild resume.exe)
                c.fn_args[op[2]] = m.ax
                m.ax = None
                state.advance()
                continue
            state.put(ir.Assign(state.loc_local(op[2]), m.ax), c.cur)
            m.ax = None
            c.cur = None
            state.advance()
            continue
        if kind == "addm_ax_bp":  # LOCAL int var = var + ax expression, e.g.
            local = state.loc_local(op[2])  # `X% = X% + 1` (no INCR fast path
            state.put(  # for bp-relative locals -- witnessed t1_local1)
                ir.Assign(local, ir.BinOp("+", local, _rgrp("+", m.ax))),
                c.cur,
            )
            m.ax = None
            c.cur = None
            state.advance()
            continue
        if kind == "subm_ax_bp":  # LOCAL int var = var - ax expression, the
            local = state.loc_local(op[2])  # subtract sibling of addm_ax_bp
            state.put(  # (wild horses.exe)
                ir.Assign(local, ir.BinOp("-", local, _rgrp("-", m.ax))),
                c.cur,
            )
            m.ax = None
            c.cur = None
            state.advance()
            continue
        if handlers.os_system(state, op, addr, kind):
            continue
        if handlers.sound(state, op, addr, kind):
            continue
        if kind == "key_on" or kind == "key_off":  # KEY ON / KEY OFF
            state.put(ir.Key(kind == "key_on"), c.cur)
            c.cur = None
            state.advance()
            continue
        if kind == "key_macro":  # KEY n, s$: n in ax, macro on sstack
            state.put(ir.KeyDef(m.ax, e.sstack.pop()), c.cur)
            m.ax = None
            c.cur = None
            state.advance()
            continue
        if handlers.write_ops(state, op, addr, kind):
            continue
        if kind == "shortstr":  # materialize the 1-char literal staged at
            # [002E] -- the FOR-mode-keyword form of OPEN (`OPEN f$ FOR
            # OUTPUT AS #n`) desugars its keyword to a packed 1-char string
            # at compile time instead of a real pooled literal, so this
            # doesn't go through the normal sstack push (wild nvginst.exe).
            if e.pend_shortstr is None:
                raise ValueError(f"shortstr without a staged literal at {addr:#x}")
            if e.pend_shortstr & 0xFF != 1:
                raise ValueError(f"shortstr with length != 1 at {addr:#x}")
            e.pend_mode_lit = ir.StrLit(chr(e.pend_shortstr >> 8))
            e.pend_shortstr = None
            state.advance()
            continue
        if kind == "movsi":  # string operand by descriptor
            # VARPTR$(variable) materializes the five-byte pointer string by
            # staging the current ES:SI address in [0032]:[0030], then using
            # the packed descriptor in [002E]. Scalar and array-element
            # forms share this exact chain (probe_varptrs_scalar and
            # probe_varptrs_arr); only the address source differs.
            if (
                c.k + 8 < len(img.ops)
                and img.ops[c.k + 1][1] == "movdx"
                and img.ops[c.k + 2][1] == "movesdx"
                and img.ops[c.k + 3][1] == "movm_imm"
                and img.ops[c.k + 3][2] == 0x2E
                and img.ops[c.k + 4] == (img.ops[c.k + 4][0], "movm_es", 0x32)
                and img.ops[c.k + 5] == (img.ops[c.k + 5][0], "movm_si", 0x30)
                and img.ops[c.k + 6][1] == "shortstr"
                and img.ops[c.k + 7][1] == "movsi"
                and img.ops[c.k + 8][1] == "strassign"
            ):
                src = l.slot_info.get(op[2])
                if src is not None:
                    if src["rank"] != 1:
                        raise ValueError(f"VARPTR$ rank-{src['rank']} array at {addr:#x}")
                    arg = ir.ArrayRef(src["name"], (ir.Lit(src["lo"][0]),))
                else:
                    arg = state.loc(op[2])
                state.put(
                    ir.Assign(
                        state.loc(img.ops[c.k + 7][2]),
                        ir.Call("VARPTR$", (arg,)),
                    ),
                    c.cur,
                )
                c.cur = None
                state.advance(9)
                continue
            nxt = img.ops[c.k + 1][1:] if c.k + 1 < len(img.ops) else None
            d = cast(int, op[2])
            if nxt == ("local_arr_free",):  # implicit runtime cleanup of a
                # LOCAL DYNAMIC array's heap block at SUB exit -- no BASIC
                # source spelling, so it's silently dropped (q_localarr)
                if d not in l.r_arrs:
                    frame = (
                        c.proc_frame
                        if c.proc_frame is not None
                        else c.fn_frame
                    )
                    locs = frame.locals if frame is not None else None
                    span = {d + 2 * i for i in range(_LOCAL_ARR_WORDS)}
                    if locs is None or not span <= set(locs):
                        raise ValueError(
                            f"LOCAL array free of unknown handle {d:#x} at {addr:#x}"
                        )
                    # A declared-but-never-DIMensioned LOCAL array has no
                    # populated runtime record; its exit cleanup is the first
                    # definitive evidence that this otherwise zero-filled
                    # 30-word span is an array descriptor (wild cleanup.exe /
                    # reformat.exe). Its element type is bytecode-lossy while
                    # unused, so the default SINGLE spelling is canonical.
                    _drop_local_descriptor_initializers(state, frame, span, addr)
                    name = (
                        f"V{l.lay['n_static'] + len(l.lay['rt_blocks']) + l.n_local_arrs}"
                    )
                    l.n_local_arrs += 1
                    frame.hidden_locals.update(span - {d})
                    locs[d] = f"{name}()"
                state.advance(2)
                continue
            if nxt == ("rt", 0x9C):  # push (var desc, static string-array
                # element at a constant index, or pooled literal)
                is_local = d in l.lay["strs"] or any(
                    a["str"] and a["base"] <= d < a["base"] + a["esz"] * a["count"]
                    for a in l.arrs
                )
                e.sstack.append(
                    state.loc(d) if is_local else state._pool_str(d)
                )
                state.advance(2)
                continue
            if nxt == ("spush_bp",):  # push string param [bp+si]: DEF FN body
                frame = (
                    c.proc_frame
                    if c.proc_frame is not None
                    else c.fn_frame
                )
                if (
                    frame is not None
                    and frame.locals is not None
                    and d in frame.locals
                ):
                    e.sstack.append(state.loc_local_str(d))
                elif c.fn_frame is None:
                    raise ValueError(
                        f"string BP push outside DEF FN at {addr:#x}"
                    )
                else:
                    c.fn_frame.param_offs.add(d)
                    c.fn_frame.str_offs.add(d)
                    e.sstack.append(ir.Var(f"P{d:02X}$"))
                state.advance(2)
                continue
            if nxt == ("strassign_bp",):  # pop-store string to [bp+si]
                frame = (
                    c.proc_frame
                    if c.proc_frame is not None
                    else c.fn_frame
                )
                if (
                    frame is not None
                    and frame.locals is not None
                    and d in frame.locals
                ):
                    ref = state.loc_local_str(d)
                    if e.pend_input is not None:
                        state._input_target(ref, is_str=True)
                    elif e.sstack and e.sstack[-1] is _FREAD:
                        e.sstack.pop()
                        state._fread_target(ref)
                    elif e.pend_getstr is not None:
                        num, count = e.pend_getstr
                        e.pend_getstr = None
                        state.put(ir.GetString(num, count, ref), c.cur)
                    elif e.sstack and e.sstack[-1] is _READDATA:
                        e.sstack.pop()
                        state._readdata_target(ref)
                    elif not e.sstack:
                        raise ValueError(
                            f"string LOCAL store with empty stack at {addr:#x}"
                        )
                    else:
                        state.put(ir.Assign(ref, e.sstack.pop()), c.cur)
                    c.cur = None
                elif c.fn_frame is not None:  # FN result desc at [bp+0]
                    if d != 0:
                        raise ValueError(
                            f"string store to [bp+{d}] in DEF FN body at {addr:#x}"
                        )
                    c.fn_frame.str_result = True
                    if c.fn_frame.block:  # FNx$ = expr statement
                        state.put(ir.FnResult(e.sstack.pop()), c.cur)
                        c.cur = None
                    else:  # single-line body expr
                        c.fn_frame.result = e.sstack.pop()
                else:  # caller: stage a string FN-call arg
                    if not e.sstack:
                        raise ValueError(
                            f"string BP argument store with empty stack at {addr:#x}"
                        )
                    c.fn_args[d] = e.sstack.pop()
                state.advance(2)
                continue
            if nxt == ("strassign",):  # pop-assign into a string var
                if e.pend_input is not None:  # ... as an INPUT's string read
                    state._input_target(state.loc(d), is_str=True)
                elif (
                    e.sstack and e.sstack[-1] is _FREAD
                ):  # INPUT# string target
                    e.sstack.pop()
                    state._fread_target(state.loc(d))
                elif e.pend_getstr is not None:
                    num, count = e.pend_getstr
                    e.pend_getstr = None
                    state.put(ir.GetString(num, count, state.loc(d)), c.cur)
                elif (
                    e.sstack and e.sstack[-1] is _READDATA
                ):  # READ string target
                    e.sstack.pop()
                    state._readdata_target(state.loc(d))
                else:
                    state.put(ir.Assign(state.loc(d), e.sstack.pop()), c.cur)
                c.cur = None
                state.advance(2)
                continue
            if nxt in (("far_spush",), ("far_strassign",)):
                # mov si, imm = constant ELEMENT OFFSET under ES=[blk]
                if m.pend_es is None:
                    raise ValueError(f"const far string op without ES at {addr:#x}")
                a = l.r_arrs[m.pend_es]
                if a["rank"] != 1 or not a.get("str"):
                    raise ValueError(
                        f"const-offset far string op mismatch at {addr:#x}"
                    )
                ref = ir.ArrayRef(a["name"], (ir.Lit(d // 4 + a["lo"][0]),))
                m.pend_es = None
                if nxt == ("far_spush",):
                    e.sstack.append(ref)
                else:
                    v = e.sstack.pop()
                    if v is _FREAD:  # INPUT# far string target
                        state._fread_target(ref)
                    else:
                        state.put(ir.Assign(ref, v), c.cur)
                    c.cur = None
                state.advance(2)
                continue
            if nxt == ("palette_using",):
                if m.pend_es is None:
                    raise ValueError(f"PALETTE USING without ES at {addr:#x}")
                a = l.r_arrs[m.pend_es]
                if a.get("str") or a.get("esz") != 2 or a["rank"] != 1:
                    raise ValueError(
                        f"PALETTE USING non-INTEGER rank-{a['rank']} array at {addr:#x}"
                    )
                ref = ir.ArrayRef(
                    a["name"], (ir.Lit(d // 2 + a["lo"][0]),)
                )
                m.pend_es = None
                state.put(ir.PaletteUsing(ref), c.cur)
                c.cur = None
                state.advance(2)
                continue
            if nxt == ("arg_push_array",):
                a = l.slot_info.get(d)
                if a is None or a.get("rank", 0) < 1:
                    raise ValueError(
                        f"whole-array CALL arg from non-array slot {d:#x} "
                        f"at {addr:#x}"
                    )
                c.pend_args.append(ir.ArrayRef(a["name"], ()))
                state.advance(2)
                continue
            if (
                c.k + 3 < len(img.ops)
                and img.ops[c.k + 1][1] == "movdx"
                and img.ops[c.k + 2][1] == "movesdx"
                and img.ops[c.k + 3][1] == "palette_using"
            ):
                ref = state.loc(d)
                if not isinstance(ref, ir.ArrayRef):
                    raise ValueError(f"PALETTE USING non-array operand at {addr:#x}")
                a = next((a for a in l.arrs if a["name"] == ref.name), None)
                if a is None or a.get("str") or a.get("esz") != 2 or a["rank"] != 1:
                    raise ValueError(f"PALETTE USING array mismatch at {addr:#x}")
                state.put(ir.PaletteUsing(ref), c.cur)
                c.cur = None
                state.advance(4)
                continue
            # Far array-element CALL arg: movsi d; movdx blk; movesdx; arg_push_arr
            if (
                c.k + 3 < len(img.ops)
                and img.ops[c.k + 1][1] == "movdx"
                and img.ops[c.k + 2][1] == "movesdx"
                and img.ops[c.k + 3][1] == "arg_push_arr"
            ):
                c.pend_args.append(
                    state.loc(d)
                )  # by-ref far array-element arg (resolved element)
                state.advance(4)
                continue
            # LSET/RSET/MID$= : movsi d; movdx blk; movesdx; <op> (fixed-field string)
            if (
                c.k + 3 < len(img.ops)
                and img.ops[c.k + 1][1] == "movdx"
                and img.ops[c.k + 2][1] == "movesdx"
                and img.ops[c.k + 3][1] in ("lset", "rset", "midassign")
            ):
                op3 = img.ops[c.k + 3][1]
                target = state.loc(d)
                source = e.sstack.pop()
                if op3 == "lset":
                    state.put(ir.Lset(target, source), c.cur)
                elif op3 == "rset":
                    state.put(ir.Rset(target, source), c.cur)
                else:  # MID$(target$, start) = source$: start is any
                    # expression, not just a literal (`MID$(A$, N%) = B$`,
                    # wild pwinst.exe) -- movax_m/whatever computed it
                    # already left the value in ax.
                    if m.ax is None:
                        raise ValueError(f"MID$= without start in ax at {addr:#x}")
                    state.put(ir.MidAssign(target, m.ax, source), c.cur)
                    m.ax = None
                c.cur = None
                state.advance(4)
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
            if op[2] not in l.r_arrs:
                raise ValueError(f"mov es from non-array cell {op[2]:#x} at {addr:#x}")
            m.pend_es = op[2]
            state.advance()
            continue
        if kind == "moves_bp":  # mov es,[bp+d8]: LOCAL DYNAMIC array's
            # element segment, the LOCAL-frame sibling of moves_m
            if op[2] not in l.r_arrs:
                raise ValueError(
                    f"mov es from non-array LOCAL cell {op[2]:#x} at {addr:#x}"
                )
            m.pend_es = op[2]
            state.advance()
            continue
        if kind == "far_movm_ax_disp":
            # `$DYNAMIC` constant-bound numeric arrays use a direct ES:[disp]
            # store for constant subscripts, rather than the usual indexed
            # ES:[SI] path (witnessed t1_dynconstnum).  The displacement is
            # the byte offset within a 2-byte integer array element stream.
            if m.pend_es is None:
                raise ValueError(f"direct far array store without ES at {addr:#x}")
            rec = l.r_arrs.get(m.pend_es)
            if rec is None or rec.get("str"):
                raise ValueError(f"direct far array store type mismatch at {addr:#x}")
            if op[2] & 1:
                raise ValueError(f"unaligned direct far array store at {addr:#x}")
            idx = op[2] // 2 + rec["lo"][0]
            state.put(
                ir.Assign(ir.ArrayRef(rec["name"], (ir.Lit(idx),)), m.ax),
                c.cur,
            )
            m.ax = None
            m.pend_es = None
            c.cur = None
            state.advance()
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
                isinstance(m.ax, tuple) and m.ax[0] == "inorm"
            ):  # 1-D index complete
                if l.slot_info[m.ax[1]]["rank"] != 1:
                    raise ValueError(f"bare inorm for rank-2 array at {addr:#x}")
                m.si = ("idx", m.ax[1], (m.ax[2],))
            else:
                m.si = m.ax
            m.ax = None
            state.advance()
            continue
        if handlers.filesystem(state, op, addr, kind):
            continue
        if handlers.file_random(state, op, addr, kind):
            continue

        if handlers.on_control(state, op, addr, kind):
            continue

        fp_dispatch(state, op, addr, kind)
    raise ValueError("op stream ended without the cleanup epilogue")


def decode_user_code(exe: bytes) -> list[Any]:
    """Decode user code and attach phase context to fail-loud errors."""

    diagnostics = DecodeDiagnostics()
    try:
        return _decode_user_code(exe, diagnostics=diagnostics)
    except ValueError as exc:
        message = str(exc)
        if "[phase=" in message:
            raise
        raise ValueError(f"{message} [{diagnostics.report()}]") from exc
