"""Structured-control-flow lifting: FOR/DO/WHILE/IF folds and target resolution."""

from __future__ import annotations
from typing import Any

from tbx import ir
from tbx.decode0.const import _JCC_RELOP_TRUE, _NEGATE_REL
from tbx.decode0.control_graph import frame_for
from tbx.decode0.frames import BoolTerm, IfFrame, LoopFrame
from tbx.decode0.statement_log import editing


def _lift_next(ops, k, fors, stmts, addrs, exit_folds) -> int:
    """Consume the NEXT template at ops[k] (a testw at the open FOR's test address):
    testw [step+2],8000h; 74 +3; e9 NEG; FLD lim; FCOMP v; fstsw; <73 BODY>; e9 EXIT;
    NEG: FLD lim; FCOMP v; fstsw; <76 BODY>.  Each <jcc BODY> is short, or the long
    form `jcc-inverse +3; e9 BODY` when the body is out of short reach."""
    with editing(stmts, "lift_next"):
        f = fors[-1]
        v = f.v
        lim, stp = f.lim, f.stp  # defaulted from `v` by ForFrame

        def expect(i, want):
            if i + len(want) > len(ops):
                raise ValueError("truncated NEXT template")
            for j, w in enumerate(want):
                got = ops[i + j]
                if got[1] != w[0] or any(
                    a is not None and got[2 + n] != a for n, a in enumerate(w[1:])
                ):
                    raise ValueError(f"NEXT template mismatch at {got[0]:#x}: {got} != {w}")
            return i + len(want)

        def jcc_body(i, cc, inv):
            o = ops[i]
            if o[1] == "jcc" and o[2] == cc and o[3] == f.body:
                return i + 1
            if (
                o[1] == "jcc"
                and o[2] == inv
                and o[3] == o[0] + 5
                and i + 1 < len(ops)
                and ops[i + 1][1] == "jmp"
                and ops[i + 1][2] == f.body
            ):
                return i + 2
            raise ValueError(
                f"NEXT template mismatch at {o[0]:#x}: {o} != jcc {cc:#x} BODY"
            )

        test_kind = ops[k][1]
        wide = ops[k + 3][1] == "fld64"
        i = expect(
            k,
            [
                (test_kind, stp + (6 if wide else 2), 0x8000),
                ("jcc", 0x74, None),
                ("jmp", None),
            ],
        )
        fld_kind, cmp_kind = ops[i][1], ops[i + 1][1]
        valid_pairs = {
            ("fld", "fcomp"),
            ("fld", "fcomp_bp"),
            ("fld_bp", "fcomp"),
            ("fld_bp", "fcomp_bp"),
            ("fld64", "fcomp64"),
        }
        if (fld_kind, cmp_kind) not in valid_pairs:
            raise ValueError(f"NEXT template: unexpected compare pair {ops[i:i + 2]}")
        i = expect(i, [(fld_kind, lim), (cmp_kind, v), ("fstsw",)])
        i = jcc_body(i, 0x73, 0x72)
        i = expect(i, [("jmp", None)])  # EXIT
        neg_start = i
        i = expect(i, [(fld_kind, lim), (cmp_kind, v), ("fstsw",)])
        i = jcc_body(i, 0x76, 0x77)
        if not _same_code_offset(ops[k + 2][2], ops[neg_start][0]):
            # e9 NEG must land on the second FLD
            raise ValueError("NEXT template: bad negative-path target")
        # the increment `v = v + step` was lifted as the preceding Assign -- fold it in
        inc = stmts[-1]

        def disp(x):
            return int(x.name[1:].rstrip("%!#&"), 16)

        if not (
            isinstance(inc, ir.Assign)
            and isinstance(inc.target, ir.Var)
            and disp(inc.target) == v
            and isinstance(inc.value, ir.BinOp)
            and inc.value.op == "+"
            and isinstance(inc.value.lhs, ir.Var)
            and isinstance(inc.value.rhs, ir.Var)
            and {disp(inc.value.lhs), disp(inc.value.rhs)} == {v, stp}
        ):
            raise ValueError(f"NEXT increment mismatch: {inc}")
        a = addrs[-1]
        del stmts[-1], addrs[-1]
        stmts.append(ir.NextStmt(inc.target))
        addrs.append(a)
        fors.pop()
        # EXIT FOR: a GOTO to the post-NEXT address (the op after this template) is an exit;
        # the conditional that skips it jumps to the NEXT (this stmt's addr). Fold at epilogue.
        if i < len(ops):
            exit_folds.append((ir.ExitFor(), a, ops[i][0]))
        return i


def _lift_var_step_next(ops, k, fors, stmts, addrs) -> int:
    """Consume the computed (variable) STEP FOR's NEXT template at ops[k]
    (an orax_self at the open FOR's test address): the increment `v = v +
    step` was already lifted as the preceding Assign -- fold it in, exactly
    like _lift_next. Then `or ax,ax; jns +3; jmp DESC` picks between two
    otherwise-identical `cmp [v],lim; jcc BODY` blocks (ascending JLE/JBE,
    descending JGE), each direct (short jcc) or the indirect long form
    (inverse jcc skip + jmp) -- the runtime mirror of the compile-time
    sign choice a literal step makes in the caller of this function. Both
    blocks must reference the SAME limit; that limit was unknown at header
    time (the ir.For's limit was a Lit(0) placeholder) and gets patched
    into the already-emitted statement here, the limit-side mirror of
    addm_i8's step patch-up (q_forvarstep/q_forvarstep2; wild menu.exe/
    stat.exe). A LOCAL loop var's sign test compares via cmp_bpi8 instead
    of cmp_mi8/16 (wild ziptest.exe, probe q_localvarstep); either way the
    loop var's own name is read back off the already-lifted ir.For (set
    correctly by loc/loc_local at header time) rather than reconstructed
    from the bp-offset/disp, since the two frames use different name
    schemes (V#### vs L##%)."""
    with editing(stmts, "lift_var_step_next"):
        f = fors[-1]
        v = f.v

        def branch(i, wantcc, invcc):
            o = ops[i] if i < len(ops) else None
            if o is None or o[1] not in ("cmp_mi8", "cmp_mi16", "cmp_bpi8") or o[2] != v:
                raise ValueError(f"FOR-STEP sign test: expected cmp [v] at index {i}")
            lim = o[3]
            nxt = ops[i + 1] if i + 1 < len(ops) else None
            if (
                nxt is not None
                and nxt[1] == "jcc"
                and nxt[2] in wantcc
                and nxt[3] == f.body
            ):
                return lim, i + 2
            nxt2 = ops[i + 2] if i + 2 < len(ops) else None
            if (
                nxt is not None
                and nxt[1] == "jcc"
                and nxt[2] in invcc
                and nxt2 is not None
                and nxt2[1] == "jmp"
                and nxt2[2] == f.body
                and nxt[3] == nxt2[0] + 3
            ):
                return lim, i + 3
            raise ValueError(f"FOR-STEP sign test: branch mismatch at {o[0]:#x}")

        jns, jmp_desc = ops[k + 1], ops[k + 2]
        if (
            jns[1] != "jcc"
            or jns[2] != 0x79
            or jmp_desc[1] != "jmp"
            or jns[3] != jmp_desc[0] + 3
        ):
            raise ValueError(f"FOR-STEP sign test: expected jns+jmp at {ops[k][0]:#x}")
        asc_lim, i = branch(k + 3, (0x7E, 0x76), (0x7F, 0x77))
        skip = ops[i] if i < len(ops) else None
        if (
            skip is None
            or skip[1] != "jmp"
            or i + 1 >= len(ops)
            or ops[i + 1][0] != jmp_desc[2]
        ):
            # `skip` jumps PAST the descending block to the loop exit (unrelated
            # to jmp_desc's own target); the descending block must instead start
            # right where the JNS's negative branch lands, at index i+1.
            raise ValueError(
                f"FOR-STEP sign test: expected skip-descending jmp at {ops[k][0]:#x}"
            )
        desc_lim, i = branch(i + 1, (0x7D,), (0x7C,))
        if asc_lim != desc_lim:
            raise ValueError(
                f"FOR-STEP sign test: ascending/descending limit mismatch at {ops[k][0]:#x}"
            )

        inc = stmts[-1]
        var = stmts[f.idx].var  # the FOR's own loop var name (V#### or L##%,
        if not (  # already correctly resolved by loc/loc_local at header time)
            isinstance(inc, ir.Assign)
            and inc.target == var
            and isinstance(inc.value, ir.BinOp)
            and inc.value.op == "+"
            and var in (inc.value.lhs, inc.value.rhs)
        ):
            raise ValueError(f"FOR-STEP NEXT increment mismatch: {inc}")
        a = addrs[-1]
        del stmts[-1], addrs[-1]

        old = stmts[f.idx]
        stmts[f.idx] = ir.For(old.var, old.init, ir.Lit(asc_lim), old.step)

        stmts.append(ir.NextStmt(var))
        addrs.append(a)
        fors.pop()
        return i


def _same_code_offset(a: int, b: int) -> bool:
    """Whether two file-linear addresses name the same 16-bit code offset.

    The scanner retains a near branch's canonical first-window target. A later
    procedure can spell the same IP 64 KiB above it, so boolean short-circuit
    edges compare offsets rather than file positions (wild electron.exe).
    """
    return (a - b) % 0x10000 == 0


def _has_jmps_back(ops, exit_addr, test_addr) -> bool:
    """True iff a short `jmp test` sits immediately before the exit address -- the
    WHILE loop-back; its absence marks an inline-IF body skip. Checked
    structurally (the op FOLLOWING the jmps starts the exit) rather than at
    exit_addr-2: trace-hook stripping re-stamps the jmps onto its hook's address
    (t1_tronwh), so byte positions shift while adjacency survives."""
    for i, o in enumerate(ops):
        if o[1] == "jmps" and o[2] == test_addr:
            nxt = ops[i + 1] if i + 1 < len(ops) else None
            return nxt is not None and nxt[0] == exit_addr
    return False


def _find_jmps_back(ops, exit_addr) -> int | None:
    """Like `_has_jmps_back`, but for a bare-value head-test loop (core.py's
    own `orax` self-test branch): here there is no known `test_addr` to
    check against up front -- an event-trapping poll hook right before the
    condition's own first op stamps `state.cur` onto ITSELF, not onto the
    op after it the way trace-hook stripping does elsewhere, so the loop-
    back `jmps`'s real target can land one op past `state.cur` (wild
    rsltest.exe: `WHILE NOT INSTAT` under active event trapping). Finds the
    jmps by its OWN structural signature (immediately followed by
    exit_addr) and returns whatever it actually targets, sidestepping the
    mismatch instead of trying to predict it."""
    for i, o in enumerate(ops):
        if o[1] == "jmps":
            nxt = ops[i + 1] if i + 1 < len(ops) else None
            if nxt is not None and nxt[0] == exit_addr:
                return o[2]
    return None


def _announce(
    branch, frame: str, template: str, target, address, cond=None, block=False
):
    """Record a frame this lift opened, and return the event.

    ``template`` is what was matched; ``frame`` is what this lift concluded
    from it. Both are recorded so the conclusion can be checked against the
    template table before the lift stops drawing it.

    A frame that opens a *body* also records its condition, because the event
    is what `close_ifs` folds from: an inline IF's condition is decided here,
    at recognition, and the record has to carry it rather than leaving the
    walk's own stack as the only copy.

    The lifts are also called with plain lists from unit tests, which have no
    decode state to record into, so the recorder is optional -- but a caller
    that needs the event back has to supply one.
    """
    if branch is None:
        return None
    return branch(
        frame,
        template=template,
        target=target,
        address=address,
        cond=cond,
        block=block,
    )


def _lift_bool_tail(
    ops, k, pend_cmp, pb, put, whiles, ifs, stmts, flush, pend_outer,
    wrap_group=False, branch=None,
):
    """Consume the compound-IF second term at ops[k] (movax FFFF): dispatch 74 =
    THEN-line IfGoto; dispatch 75 = compound WHILE (jmps-back present)
    or inline-IF body. A 3+-term chain (witnessed t1_and3) cascades: each MID
    segment's dispatch jmp short-circuits into the NEXT segment's fold template
    (comb addr + the same +2/+0 AND/OR delta the first-term match uses) instead
    of exiting -- fold the condition and keep the compound open.

    `wrap_group=True` (an explicitly-parenthesized AND-group used as one
    operand of an outer OR, e.g. `(A AND B) OR (C AND D)`, wild bmaster.exe/
    ifi.exe, probe q_orofands) wraps just THIS call's own `pb.r1, r2` fold
    in `ir.Group` -- the parens are byte-significant (recompiling the
    unparenthesized-but-equivalent-precedence spelling produces different
    bytes). Only the immediate fold is wrapped, never any later outer-join
    combine, matching the source's own single level of explicit parens.

    A combinator SWITCH (`A AND B OR C` = `(A AND B) OR C`, precedence-correct
    left grouping since AND/OR chain byte-identically either way for a single
    trailing term: wild state.exe/state87.exe, probe q_mixedbool2) also
    continues the SAME flat fold when the switch target is the immediately
    NEXT term (`ops[k+6]`). When it is NOT (`A OR B AND C` = `A OR (B AND
    C)`: B and C bind tighter and must resolve as their OWN group before
    joining A -- wild wb.exe/grdscn.exe/mcmurphy.exe, probes q_mixedbool5/
    q_mixedbool6), folding is DEFERRED: this call returns with `pend_bool =
    None` and a fresh `pend_outer` frame; the ordinary dispatch loop then
    re-enters `_match_bool_term1` at `ops[k+6]` as if it were a brand new
    top-level compound-IF, and THAT group's own eventual close (in a later
    call here, `pend_outer` threaded through unchanged) folds
    `LogOp(pend_outer.op, pend_outer.r1, <inner group's cond>)` instead
    of emitting directly, using `pend_outer.start` as the statement's
    address. Only one level of deferral is verified; a second one raises.

    Returns (next op index, still-open pend_bool or None, pend_outer or
    None)."""
    with editing(stmts, "lift_bool_tail"):
        comb = "andaxbx" if pb.op == "AND" else "orax"
        want = [o[1] for o in ops[k : k + 6]]
        # A FAR exit target (segment-crossing THEN/exit, wild mf.exe) uses
        # `jmpf` (5 bytes, EA) instead of the near `jmp` (3 bytes, E9) here --
        # same op-kind breadth `direct_bool` already accepts for its own
        # dispatch-tail jmp.
        if want[:5] == ["movax", "jcc", "incax", comb, "jcc"] and want[5] in (
            "jmp",
            "jmpf",
        ):
            pass
        else:
            raise ValueError(f"compound-IF tail mismatch at {ops[k][0]:#x}")
        if ops[k][2] != 0xFFFF:
            raise ValueError(f"compound-IF tail mismatch at {ops[k][0]:#x}")
        m_jcc, f_jcc, f_jmp = ops[k + 1], ops[k + 4], ops[k + 5]
        if m_jcc[3] != ops[k + 3][0] or m_jcc[2] not in _JCC_RELOP_TRUE:
            raise ValueError(f"compound-IF tail: bad Jcc skip at {m_jcc[0]:#x}")
        jmp_len = 5 if f_jmp[1] == "jmpf" else 3
        if f_jcc[2] not in (0x74, 0x75) or f_jcc[3] != f_jmp[0] + jmp_len:
            raise ValueError(f"compound-IF tail: bad dispatch pair at {f_jcc[0]:#x}")
        delta = 2 if pb.op == "AND" else 0
        if not _same_code_offset(pb.sc, ops[k + 3][0] + delta):
            raise ValueError(
                f"compound-IF: short-circuit target mismatch at {ops[k][0]:#x}"
            )
        r2 = ir.RelOp(_JCC_RELOP_TRUE[m_jcc[2]], *pend_cmp)
        cond = ir.LogOp(pb.op, pb.r1, r2)
        if wrap_group:
            cond = ir.Group(cond)
        # own_op -- how `cond` (just folded) joins whatever comes next -- is
        # this segment's OWN dispatch polarity (f_jcc), a fact independent of
        # pb.op (the operator that folded r1 with r2 to make `cond`): e.g.
        # wild state.exe's (A AND B) joins C via OR even though A folded with B
        # via AND. The candidate search below only LOCATES and shape-checks
        # whatever sits at the short-circuit target -- own_comb for a same-op
        # cascade continuation, alt_comb for a differently-operated segment/
        # GROUP -- it never changes the join operator itself (a bug found via
        # oracle probe q_mixedbool6: returning the ALT candidate's own label
        # for a multi-term GROUP silently swapped AND/OR in the outer join).
        own_op = {0x75: "AND", 0x74: "OR"}[f_jcc[2]]
        own_comb = "andaxbx" if own_op == "AND" else "orax"
        own_delta = 2 if own_op == "AND" else 0
        alt_comb = "orax" if own_comb == "andaxbx" else "andaxbx"
        alt_delta = 0 if own_delta == 2 else 2
        seen_materialize = False
        for j in range(k + 6, min(k + 36, len(ops) - 3)):
            if ops[j][1] != "movax" or ops[j][2] != 0xFFFF:
                continue
            nxt3 = [o[1] for o in ops[j + 1 : j + 4]]
            for candidate_comb, candidate_delta in (
                (own_comb, own_delta),
                (alt_comb, alt_delta),
            ):
                if (
                    nxt3 == ["jcc", "incax", candidate_comb]
                    and _same_code_offset(f_jmp[2], ops[j + 3][0] + candidate_delta)
                ):
                    if not seen_materialize:  # immediately-next term: flat fold
                        return (
                            k + 6,
                            BoolTerm(
                                r1=cond, op=own_op, sc=f_jmp[2], start=pb.start
                            ),
                            pend_outer,
                        )
                    # a multi-term inner GROUP starts at k+6 instead -- defer
                    if pend_outer is not None:
                        # Left-associative cascade of GROUPS (`(A AND B) OR
                        # (C AND D) OR (E AND F)`, wild mcmurphy.exe, probe
                        # q_mixedbool7): fold the prior deferred group into
                        # `cond` now, the same left-fold every other cascade
                        # here uses, then keep waiting -- own_op governs how
                        # this new combined accumulator joins the NEXT group.
                        cond = ir.LogOp(pend_outer.op, pend_outer.r1, cond)
                        outer_start = pend_outer.start
                    else:
                        outer_start = pb.start
                    return (
                        k + 6,
                        None,
                        BoolTerm(r1=cond, op=own_op, start=outer_start),
                    )
            seen_materialize = True
        final_cond, final_start = cond, pb.start
        if pend_outer is not None:
            final_cond = ir.LogOp(pend_outer.op, pend_outer.r1, cond)
            final_start = pend_outer.start
        if f_jcc[2] == 0x74:
            put(ir.IfGoto(final_cond, ("addr", f_jmp[2])), final_start)
        elif frame_for(
            template := (
                "bool_tail_loopback"
                if _has_jmps_back(ops, f_jmp[2], final_start)
                else "bool_tail_skip"
            )
        ) == "loop":
            # The lift recognises the template -- a jump back to the test
            # address before the exit -- and the table says what it denotes.
            # Which of the two it is used to be decided here, from the same
            # evidence, which is the coupling this chapter removes.
            put(ir.While(final_cond), final_start)
            _announce(branch, "loop", template, f_jmp[2], final_start)
            whiles.append(LoopFrame(test=final_start, exit=f_jmp[2]))
        else:
            flush()
            event = _announce(
                branch, "if", template, f_jmp[2], final_start, cond=final_cond
            )
            ifs.append(IfFrame(seq=event.seq))
        return k + 6, None, None


def _noshift(index, delta):
    """No queued fold regions to move -- what the eager fold always had.

    A `DO` spliced in ahead of a body moves every list position after it,
    including the ones a deferred fold region is recorded as. Under the eager
    fold there were none to move: the region was one statement before any loop
    lift ran. `shift` is how the walk tells the lifts otherwise.
    """


def _lift_do_tail(ops, k, pend_cmp, stmts, addrs, put, cur, shift=_noshift):
    """Tail-test DO ... LOOP WHILE/UNTIL: mov ax,0FFFF; Jcc(R) +1; inc ax; or ax,ax;
    <cc BACKWARD> where BACKWARD targets an earlier statement (the loop body start) --
    no trailing e9 (the conditional jcc IS the back-edge). Splice a bare `DO` before
    the body and emit `LOOP WHILE/UNTIL cond` here. cc 75 = continue-if-true = WHILE;
    cc 74 = continue-if-false = UNTIL. Returns the next op index, or None if no match.
    """
    with editing(stmts, "lift_do_tail"):
        want = ["movax", "jcc", "incax", "orax", "jcc"]
        if k + len(want) > len(ops) or [o[1] for o in ops[k : k + len(want)]] != want:
            return None
        m_jcc, back_jcc = ops[k + 1], ops[k + 4]
        if m_jcc[3] != ops[k + 3][0] or m_jcc[2] not in _JCC_RELOP_TRUE:
            return None
        back = back_jcc[3]
        if back_jcc[2] not in (0x74, 0x75) or back >= ops[k][0] or back not in addrs:
            return None
        cond = ir.RelOp(_JCC_RELOP_TRUE[m_jcc[2]], *pend_cmp)
        kind = "WHILE" if back_jcc[2] == 0x75 else "UNTIL"
        idx = addrs.index(back)  # splice `DO` before the body start
        stmts.insert(idx, ir.Do(None))
        addrs.insert(idx, None)
        shift(idx, 1)
        put(ir.Loop(kind, cond), cur)
        return k + len(want)


def _lift_bool_do_tail(ops, k, pend_cmp, pb, stmts, addrs, put, shift=_noshift):
    """Compound-IF second term ending in a tail-test DO ... LOOP WHILE/UNTIL:
    same shape as `_lift_do_tail` (materialization's Jcc IS the backward
    loop edge, no trailing jmp), except the combining op at index 3 is the
    compound's AND/OR fold (from `pb`) rather than a bare self-test `or ax,ax`.
    Returns the next op index, or None if no match (caller falls back to
    `_lift_bool_tail`'s dispatch-jcc+jmp shape).

    TWO polarities occur, exactly the pair `_lift_while` already distinguishes
    for a SIMPLE tail test:

    * the combining jcc IS the backward retry edge (no trailing jmp), or
    * the combining jcc is the forward EXIT and the template's own trailing
      `jmp` is the backward retry edge -- the mirror image, since here the jcc
      causes the exit and falling through to the jmp retries.

    Only the first was handled, so the second silently fell through to
    `_lift_bool_tail` and the loop was consumed as a compound *IF*: the DO and
    LOOP statements never materialized at all, and the body's own statements
    were left dangling in the enclosing block (wild tbd73.exe, TBW73.INC:727:
    `LOOP UNTIL (ans$ = CHR$(13)) OR (ans$ = CHR$(27))` closing `SUB
    Makelmenu`'s `DO`, surfacing only as `jump target 0xd49b is not a statement
    start` from the IF on the line before it). Fixture t1_boolloopuntil."""
    with editing(stmts, "lift_bool_do_tail"):
        comb = "andaxbx" if pb.op == "AND" else "orax"
        want = ["movax", "jcc", "incax", comb, "jcc"]
        if k + len(want) > len(ops) or [o[1] for o in ops[k : k + len(want)]] != want:
            return None
        m_jcc, back_jcc = ops[k + 1], ops[k + 4]
        if m_jcc[3] != ops[k + 3][0] or m_jcc[2] not in _JCC_RELOP_TRUE:
            return None
        if not _same_code_offset(pb.sc, ops[k + 3][0] + (2 if pb.op == "AND" else 0)):
            return None
        if back_jcc[2] not in (0x74, 0x75):
            return None
        back, nk = back_jcc[3], k + len(want)
        if back < ops[k][0] and back in addrs:  # the jcc itself retries
            kind = "WHILE" if back_jcc[2] == 0x75 else "UNTIL"
        else:  # ...or the trailing jmp does, with the jcc as the exit
            jmp = ops[nk] if nk < len(ops) else None
            if jmp is None or jmp[1] != "jmp" or back != jmp[0] + 3:
                return None
            back, nk = jmp[2], nk + 1
            if back >= ops[k][0] or back not in addrs:
                return None
            kind = "WHILE" if back_jcc[2] == 0x74 else "UNTIL"
        r2 = ir.RelOp(_JCC_RELOP_TRUE[m_jcc[2]], *pend_cmp)
        cond = ir.LogOp(pb.op, pb.r1, r2)
        idx = addrs.index(back)  # splice `DO` before the body start
        stmts.insert(idx, ir.Do(None))
        addrs.insert(idx, None)
        shift(idx, 1)
        put(ir.Loop(kind, cond), pb.start)
        return nk


def _lift_while(
    ops, k, pend_cmp, whiles, dos, ifs, stmts, addrs, put, flush, cur,
    block_ifs=None, branch=None, folded_away=frozenset(), shift=_noshift,
) -> int:
    """Consume the materialized loop test at ops[k] (mov ax,0FFFF):
    Jcc(R) +1; inc ax; or ax,ax; <cc> +3; e9 EXIT. With a loop-back before
    EXIT it is a head-test loop -- `DO WHILE cond` (cc 75, continue-if-true) or
    `DO UNTIL cond` (cc 74, continue-if-false); without one it is an inline-IF body
    skip (cc 75 only), OR (if the trailing jmp itself is backward -- see below)
    a TAIL-test `DO...LOOP WHILE/UNTIL` whose body ends in something (e.g. a
    nested FOR...NEXT) that leaves no separate `jmps`-back edge for
    `_has_jmps_back` to find.

    An explicit source `NOT` wrapping the tested expression (only witnessed on
    a string comparison, wild kinder.exe: `strcmp` has no direct-jcc-flip like
    a numeric relop, so negating it takes a real `F7 D0 notax` between the
    materialization's `inc ax` and the `or ax,ax` self-test) inserts one extra
    op into the usual six; detected by probing for it before matching `want`."""
    with editing(stmts, "lift_while"):
        negate = k + 3 < len(ops) and ops[k + 3][1] == "notax"
        off = 1 if negate else 0
        want = ["movax", "jcc", "incax"] + (["notax"] if negate else []) + [
            "orax",
            "jcc",
            "jmp",
        ]
        if k + len(want) > len(ops) or [o[1] for o in ops[k : k + len(want)]] != want:
            raise ValueError(f"materialization template mismatch at {ops[k][0]:#x}")
        m_jcc, exit_jcc, exit_jmp = ops[k + 1], ops[k + 4 + off], ops[k + 5 + off]
        if m_jcc[3] != ops[k + 3][0]:  # Jcc +1 skips exactly the inc ax
            raise ValueError("materialization: bad Jcc skip")
        if m_jcc[2] not in _JCC_RELOP_TRUE:
            raise ValueError(f"unhandled materialization jcc {m_jcc[2]:02x}")
        if exit_jcc[2] not in (0x74, 0x75) or exit_jcc[3] != exit_jmp[0] + 3:
            raise ValueError("DO/WHILE: bad exit pair")
        cond = ir.RelOp(_JCC_RELOP_TRUE[m_jcc[2]], *pend_cmp)
        if negate:
            cond = ir.Not(cond)
        if _has_jmps_back(ops, exit_jmp[2], cur):  # head-test DO loop
            kind = "WHILE" if exit_jcc[2] == 0x75 else "UNTIL"
            put(ir.Do(kind, cond), cur)
            dos.append(LoopFrame(test=cur, exit=exit_jmp[2]))
        elif (
            exit_jmp[2] < ops[k][0]
            and exit_jmp[2] in addrs
            and exit_jmp[2] not in folded_away
        ):
            # Tail-test DO...LOOP WHILE/UNTIL: the retry edge is THIS
            # template's own trailing jmp (backward, landing on a real
            # statement), not a separate jmps elsewhere (e.g. the body ends
            # in a nested FOR...NEXT, which leaves no plain jmps-back for
            # _has_jmps_back to find) -- the mirror image of _lift_do_tail's
            # polarity, since here exit_jcc CAUSES the exit and falling
            # through (to the jmp) retries, rather than the jcc itself being
            # the retry edge. Checked BEFORE the inline-IF branch below,
            # since a backward jmp can never be a genuine inline-IF's
            # forward body-skip -- an UNTIL-form tail loop (cc 75) would
            # otherwise be misclassified there. Confirmed against wild
            # metric.exe (probe q_nestedfor: a DO...LOOP WHILE wrapping a
            # FOR...NEXT, ending a GOSUB'd routine).
            loop_kind = "WHILE" if exit_jcc[2] == 0x74 else "UNTIL"
            idx = addrs.index(exit_jmp[2])
            stmts.insert(idx, ir.Do(None))
            addrs.insert(idx, None)
            shift(idx, 1)
            put(ir.Loop(loop_kind, cond), cur)
        elif exit_jcc[2] == 0x75:  # inline-IF (forward skip, by exclusion above)
            flush()
            spelled_block = False
            if block_ifs is not None and isinstance(cond, ir.RelOp):
                # A SIMPLE condition that reached here MATERIALIZED (this function
                # consumes the movax-FFFF template), and a genuinely single-line
                # `IF <simple> THEN <stmt>` does NOT materialize -- it compiles a
                # bare dispatch pair (zz_sub7/zz_mdeffn2: `jcc; jmp`, no movax
                # FFFF, both byte-exact as inline). So this is positive evidence
                # the SOURCE spelled a multi-line block IF. Measured on our own
                # oracle: the two spellings of one two-statement body compile 71
                # differing bytes, and rendering the block form inline loses 16 --
                # the standing round-trip mismatch on zz_bif1/zz_bif4.
                #
                # Recorded as EVIDENCE for `_fold_if` rather than acted on here:
                # the ELSE arms are reconstructed there, so building an IfBlock at
                # this point would bypass that and drop the ELSE (t1_tronif /
                # t1_tronerb, whose hooks then misalign with the physical lines).
                # Compound conditions materialize either way, so only a plain
                # RelOp counts.
                block_ifs.add(cur)
                spelled_block = True
            event = _announce(
                branch,
                "if",
                "materialized_test_skip",
                exit_jmp[2],
                cur,
                cond=cond,
                block=spelled_block,
            )
            ifs.append(IfFrame(seq=event.seq))
        else:
            raise ValueError(f"unhandled materialized test at {ops[k][0]:#x}")
        return k + len(want)


def _inline_safe(body) -> bool:
    """A THEN/ELSE body renders on one line only if no nested IF precedes the last
    statement (else a trailing statement would bind to the inner IF -- it must block).

    A BLOCK-structured statement cannot render inline at all, wherever it sits --
    including last, where the nested-IF rule above would otherwise allow it:
    `IF c THEN SELECT CASE ...` is not valid source, and TB rejects it outright
    with `Error 470: Block/scanned statements not allowed here`. So any body
    containing one forces the enclosing IF to a block.

    Witnessed by wild tbd73.exe, TBW73.INC:510: `IF hmenuopen AND (ans1$ =
    CHR$(75) OR ans1$ = CHR$(77)) THEN` opens a block whose body is a
    `SELECT CASE`. Its condition is COMPOUND, so round 35's `block_ifs`
    discriminator (plain-RelOp only) never promoted it and it stayed an
    IfInline -- decoding cleanly and emitting unrecompilable source, which is
    what kept tbd73's round trip broken after it started decoding end to end.
    Fixture t1_ifblockselect."""
    if any(isinstance(b, (ir.SelectCase, ir.IfBlock)) for b in body):
        return False
    return not any(isinstance(b, (ir.IfInline, ir.IfBlock)) for b in body[:-1])


def _body_has_target(body, targets, stmt_addr) -> bool:
    """True if any statement in `body` -- or, recursively, inside a nested
    IfInline's own body -- is a jump target. A numbered nested-IF interior
    line can sit two or more inline-IF levels deep before any of them gets
    block-folded (wild inv87.exe: neither level is an IfBlock yet at the
    point this check needs to fire), so a single flat `any(...)` over just
    the immediate children isn't enough."""
    if stmt_addr is None:
        return False
    for b in body:
        if stmt_addr.get(id(b)) in targets:
            return True
        if isinstance(b, ir.IfInline) and _body_has_target(b.body, targets, stmt_addr):
            return True
    return False


def _fold_body(body, targets=frozenset(), stmt_addr=None, block_ifs=None):
    """Recursively block-fold nested non-inline-safe IFs within an arm/else body
    (bodies carry no Goto-else marker; only the rendering split applies here) --
    also block-folds an inline-safe IfInline whose OWN body contains a jump
    target, the same "second leg" `_fold_if` applies at the top level, just
    applied recursively: a numbered nested-IF interior line can sit two (or
    more) block levels deep (wild inv87.exe), not only directly under the
    outermost IF.

    `b` itself (not just something inside `b.body`) can ALSO be a jump
    target -- a GOTO landing on the header of this very nested inline-IF
    (wild state.exe) -- so the replacement node must inherit `b`'s own
    `stmt_addr` entry, the same transfer `_fold_body_ifgotos` already does
    when it discards a node; otherwise the address stays keyed to the
    discarded `ir.IfInline` and `_resolve_targets` can never find it."""
    with editing(body, "fold_body"):
        if stmt_addr is not None and any(
            isinstance(b, ir.IfInline)
            and b.body
            and isinstance(b.body[-1], ir.Goto)
            and isinstance(b.body[-1].target, tuple)
            and b.body[-1].target[0] == "addr"
            for b in body
        ):
            # A nested IF inside THIS body carries an else-skip Goto, so the body
            # needs the full `_fold_if` treatment (its FIRST leg is what turns that
            # Goto into an ELSE arm) -- not just the block-fold below. Delegating
            # rather than duplicating keeps one implementation of the ELSE
            # reconstruction. Guarded on the marker actually being present so no
            # body without one changes shape (wild tbd73.exe: TBW73.INC's
            # DEF FNCurdisplay nests block IF/ELSE four deep, and its ELSE arms
            # were left as siblings with the skip-Goto surviving).
            # The skip lands on the ENCLOSING structure's merge point, which is
            # outside this body -- so pass it as `bound`, the parameter _fold_if
            # already has for "else-skip to the region's merge", or its end_idx
            # search finds nothing and the leg is skipped.
            marker = next(
                b.body[-1].target[1]
                for b in body
                if isinstance(b, ir.IfInline)
                and b.body
                and isinstance(b.body[-1], ir.Goto)
                and isinstance(b.body[-1].target, tuple)
                and b.body[-1].target[0] == "addr"
            )
            addrs = [stmt_addr.get(id(b)) for b in body]
            folded, folded_addrs = _fold_if(
                list(body),
                addrs,
                bound=marker,
                targets=targets,
                stmt_addr=stmt_addr,
                block_ifs=block_ifs,
            )
            # `_fold_if` returns a rebuilt statement's address in its addrs
            # list, which is how a TOP-LEVEL caller keeps it. A body has no
            # address list, so the address has to be claimed here or it is
            # lost with the node that owned it -- and a GOTO into this body
            # can then never resolve (wild state.exe, `jump target 0xe179 is
            # not a statement start`: a nested inline IF that is itself a
            # jump target, rebuilt into a block by the ELSE reconstruction).
            for statement, address in zip(folded, folded_addrs):
                if address is not None:
                    stmt_addr.claim(statement, address)
            body = tuple(folded)
        out = []
        for b in body:
            if isinstance(b, ir.IfInline) and (
                not _inline_safe(b.body)
                or _body_has_target(b.body, targets, stmt_addr)
                # `_fold_if`'s third leg, applied recursively: the BYTES say this
                # nested IF was spelled multi-line too (zz_bif4, a block IF whose
                # own first body statement is another block IF).
                or (
                    block_ifs is not None
                    and stmt_addr is not None
                    and stmt_addr.get(id(b)) in block_ifs
                )
            ):
                new_b = ir.IfBlock(
                    ((b.cond, _fold_body(b.body, targets, stmt_addr, block_ifs)),), None
                )
                if stmt_addr is not None:
                    a = stmt_addr.get(id(b))
                    if a is not None:
                        stmt_addr.claim(new_b, a)
                out.append(new_b)
            else:
                out.append(b)
        return tuple(out)


def _apply_exit_folds(stmts, addrs, exit_folds):
    """EXIT FOR/LOOP/SUB/DEF folds: rewrite the early-exit GOTO to the
    loop/proc exit, then fold `IF c THEN <skip>` + EXIT into `IF negate(c) THEN EXIT`.
    """
    with editing(stmts, "apply_exit_folds"):
        for exit_stmt, skip_addr, exit_addr in exit_folds:
            for i, s in enumerate(stmts):
                if isinstance(s, ir.Goto) and s.target == ("addr", exit_addr):
                    stmts[i] = exit_stmt
            i = 0
            while i + 1 < len(stmts):
                if (
                    isinstance(stmts[i], ir.IfGoto)
                    and stmts[i].target == ("addr", skip_addr)
                    and stmts[i + 1] == exit_stmt
                ):
                    c = stmts[i].cond
                    if not isinstance(c, ir.RelOp):
                        raise ValueError(f"EXIT-IF fold: non-relational cond {c!r}")
                    stmts[i] = ir.IfInline(
                        ir.RelOp(_NEGATE_REL[c.op], c.lhs, c.rhs), (exit_stmt,)
                    )
                    del stmts[i + 1], addrs[i + 1]
                i += 1


def _fold_body_ifgotos(body, end_addr, stmt_addr=None):
    """An `IF c THEN <line>` followed by MORE statements on the same line is
    not spellable source (TB raises Error 431, end-of-line expected, after
    `THEN <line>`); when such an IfGoto inside an inline-IF body targets the
    body's own END address, the source was a nested inline IF whose skip-jcc
    merged with the enclosing close -- negate the compare and nest the tail
    (witnessed t1_nestif / wild vhfprop.exe). Other targets are left alone
    (fail-loud at recompile until a fixture witnesses them). The negated
    IfInline occupies the CONSUMED IfGoto's own position, so its recorded
    address (if any) transfers to the new node -- otherwise a GOTO targeting
    that position (from elsewhere in the program, a NUMBERED nested-IF
    interior line, wild inv87.exe) can never resolve, since the original
    node no longer exists anywhere in the tree (gap: the address stayed
    keyed to a discarded object)."""
    with editing(body, "fold_body_ifgotos"):
        for j, b in enumerate(body[:-1]):
            if (
                isinstance(b, ir.IfGoto)
                and b.target == ("addr", end_addr)
                and isinstance(b.cond, ir.RelOp)
            ):
                tail = _fold_body_ifgotos(body[j + 1 :], end_addr, stmt_addr)
                c = b.cond
                new_node = ir.IfInline(ir.RelOp(_NEGATE_REL[c.op], c.lhs, c.rhs), tail)
                if stmt_addr is not None:
                    a = stmt_addr.get(id(b))
                    if a is not None:
                        stmt_addr.claim(new_node, a)
                return body[:j] + (new_node,)
        return body


def _jump_targets(stmts) -> frozenset[int]:
    """Every address referenced as a jump target anywhere in the statement
    tree (Goto/IfGoto/Gosub, ON GOTO/GOSUB lists, ON ERROR/RESUME/ON-trap),
    including inside already-lifted IfInline bodies, IfBlock arms/ELSE and
    SelectCase arms/CASE ELSE.

    The block/SELECT arms used to be skipped, which quietly under-delivered on
    "anywhere in the tree": `targets` is what promotes an inline-safe IfInline
    to a block (`_fold_if`'s second leg, and `_body_has_target`), so a jump
    target reachable only through an arm left the enclosing IF inline and its
    interior un-addressable. Wild tbd73.exe, TBW73.INC:476-483: the compound
    `IF ans1$ = CHR$(72) OR ... THEN` block holds two SELECT CASEs, and the
    first one's CASE ELSE jumps to the SECOND one's header -- so the target
    only appears inside a CASE ELSE (`jump target 0xba64 is not a statement
    start`). Fixture t1_selelsetarget.

    SubDef/DefFn bodies are deliberately NOT walked: by the time a body is
    inside one, its own `_fold_if` pass at proc_ret/fn_ret has already run
    with its statements at top level, so its targets were collected then."""
    out = set()

    def walk(s):
        if isinstance(s, (ir.Goto, ir.IfGoto, ir.Gosub)):
            if isinstance(s.target, tuple) and s.target[0] == "addr":
                out.add(s.target[1])
        elif isinstance(s, (ir.OnGoto, ir.OnGosub)):
            for tag, a in s.targets:
                if tag == "addr":
                    out.add(a)
        elif isinstance(s, (ir.OnError, ir.Resume)) and s.target is not None:
            if isinstance(s.target, tuple) and s.target[0] == "addr":
                out.add(s.target[1])
        elif isinstance(s, ir.OnTrap):
            if isinstance(s.target, tuple) and s.target[0] == "addr":
                out.add(s.target[1])
        elif isinstance(s, ir.IfInline):
            for b in s.body:
                walk(b)
        elif isinstance(s, ir.IfBlock):
            for _cond, arm in s.arms:
                for b in arm:
                    walk(b)
            for b in s.else_body or ():
                walk(b)
        elif isinstance(s, ir.SelectCase):
            for arm in s.arms:
                for b in arm.body:
                    walk(b)
            for b in s.case_else or ():
                walk(b)

    for s in stmts:
        walk(s)
    return frozenset(out)


def _fold_if(
    stmts, addrs, bound=None, targets=frozenset(), stmt_addr=None, block_ifs=None
):
    """Fold multi-line IF blocks, address-level (before target resolution).
    A block IF/ELSE is an IfInline whose body ends in a forward Goto past its own start
    (the else-skip): strip it, take the statements up to the Goto target as the ELSE
    region (recursively folded), and flatten a lone IfBlock else into ELSEIF arms. A
    non-inline-safe IfInline with no else becomes a single-arm block. `bound` is the
    merge address that terminates the region: an else-skip Goto to it lands at the
    region end (used when recursing into an ELSE region that excludes the merge stmt).
    `targets` is the program-wide jump-target address set: a region containing a
    targeted address cannot be an ELSE body (block interiors aren't addressable, so
    the source can only have spelled it as `IF c THEN ...: GOTO n` over separate
    lines -- witnessed q_ifgoto2/wild onelab87.exe); the fold is skipped and the
    trailing Goto stays in the inline body. Returns new (stmts, addrs) lists."""
    with editing(stmts, "fold_if"):
        out_s, out_a = [], []
        i = 0
        while i < len(stmts):
            s, a = stmts[i], addrs[i]
            if (
                isinstance(s, ir.IfInline)
                and s.body
                and isinstance(s.body[-1], ir.Goto)
                and isinstance(s.body[-1].target, tuple)
                and s.body[-1].target[0] == "addr"
                and a is not None
                and s.body[-1].target[1] > a
            ):
                end = s.body[-1].target[1]
                end_idx = next(
                    (j for j in range(i + 1, len(stmts)) if addrs[j] == end), None
                )
                if end_idx is None and end == bound:  # else-skip to the region's merge
                    end_idx = len(stmts)
                if end_idx is not None and any(
                    t in targets for t in addrs[i + 1 : end_idx] if t is not None
                ):
                    end_idx = None  # targeted interior: not an ELSE region
                if end_idx is not None:
                    arms = [(s.cond, _fold_body(s.body[:-1], targets, stmt_addr, block_ifs))]
                    else_s, _ = _fold_if(
                        stmts[i + 1 : end_idx],
                        addrs[i + 1 : end_idx],
                        bound=end,
                        targets=targets,
                        stmt_addr=stmt_addr,
                        block_ifs=block_ifs,
                    )
                    if len(else_s) == 1 and isinstance(else_s[0], ir.IfBlock):
                        arms.extend(else_s[0].arms)  # ELSEIF flatten
                        else_body = else_s[0].else_body
                    else:
                        else_body = tuple(else_s) if else_s else None
                    out_s.append(ir.IfBlock(tuple(arms), else_body))
                    out_a.append(a)
                    i = end_idx
                    continue
            if isinstance(s, ir.IfInline) and (
                not _inline_safe(s.body)
                or _body_has_target(s.body, targets, stmt_addr)
                # Third leg: the BYTES say the source spelled this IF multi-line
                # (see _lift_while's `block_ifs`). Checked after the ELSE leg
                # above, so an IF with an ELSE still reconstructs its arms there.
                or (block_ifs is not None and a is not None and a in block_ifs)
            ):
                # Second leg: a body statement is a jump target -- the source was
                # a block IF with a NUMBERED interior line jumped into from
                # outside (witnessed t1_blkgoto / wild inv87.exe); the block form
                # lets emit0 number that physical line (ir.BodyLine).
                out_s.append(
                    ir.IfBlock(
                        ((s.cond, _fold_body(s.body, targets, stmt_addr, block_ifs)),),
                        None,
                    )
                )
                out_a.append(a)
                i += 1
                continue
            out_s.append(s)
            out_a.append(a)
            i += 1
        return out_s, out_a


def _lift_midblock_troff(stmts, addrs, trace_tbl, orphans, stmt_addr, hook_seq):
    """Region ends INSIDE a block body (t1_troffin): TROFF sits between two body
    statements, so its hook stamps a body statement's code and never surfaces as a
    top-level addr -- it shows up as an `orphan` (a trace_tbl key that is not a
    top-level statement start). Synthesize TRON before the block, splice a TROFF into
    the block body before the demoted (first post-region) body statement, force the
    single-arm block form, and report how many leading PHYSICAL lines the block traces
    (IF header + traced leaves + the TROFF) so emit0 numbers only that prefix.

    Returns (new_stmts, new_addrs, fixed_lines, partial). Only the witnessed shape
    is handled -- a lone traced block whose immediate leaf body owns every orphan
    hook; anything else raises loudly, in keeping with the fail-loud discipline."""
    with editing(stmts, "lift_midblock_troff"):
        top_hooked = [i for i, a in enumerate(addrs) if a in trace_tbl]
        blocks = [i for i in top_hooked if isinstance(stmts[i], (ir.IfInline, ir.IfBlock))]
        if len(top_hooked) != 1 or len(blocks) != 1:
            raise ValueError("TROFF inside a block: only a lone traced block is supported")
        bi = blocks[0]
        s = stmts[bi]
        if isinstance(s, ir.IfInline):
            cond, body = s.cond, list(s.body)
        else:
            if len(s.arms) != 1 or s.else_body is not None:
                raise ValueError("TROFF inside a block: ELSE/ELSEIF unsupported")
            cond, body = s.arms[0][0], list(s.arms[0][1])
        body_addr = [stmt_addr.get(id(b)) for b in body]
        if any(a is None for a in body_addr):
            raise ValueError("TROFF inside a block: body address missing")
        if not set(orphans) <= set(body_addr):
            raise ValueError("TROFF inside a block: orphan hook not in the block body")
        hooked_body = [j for j, a in enumerate(body_addr) if a in trace_tbl]
        if hooked_body != list(range(len(hooked_body))):
            raise ValueError("TROFF inside a block: non-prefix trace run")
        if len(hook_seq) != 1 + len(hooked_body):
            raise ValueError("TROFF inside a block: hooks unaccounted")
        dem = hooked_body[-1]  # demoted body index: TROFF goes before it
        if any(isinstance(body[j], (ir.IfInline, ir.IfBlock)) for j in hooked_body[:-1]):
            raise ValueError("TROFF inside a block: nested traced block unsupported")
        new_body = body[:dem] + [ir.Troff()] + body[dem:]
        new_block = ir.IfBlock(((cond, tuple(new_body)),), None)
        traced_phys = 1 + dem + 1  # IF header + traced leaves + TROFF line
        floor = hook_seq[traced_phys - 1] + 10  # post-block free lines clear the hooks
        new_s, new_a, fixed_lines, partial = [], [], {}, {}
        for i, (st, a) in enumerate(zip(stmts, addrs)):
            if i == bi:
                new_s.append(ir.Tron())  # TRON's own line is free
                new_a.append(None)
                bidx = len(new_s)
                fixed_lines[bidx] = trace_tbl[a]  # block's first physical line = first hook
                partial[bidx] = traced_phys
                new_s.append(new_block)
                new_a.append(a)
            else:
                if i == bi + 1:
                    fixed_lines[len(new_s)] = floor  # first post-region statement
                new_s.append(st)
                new_a.append(a)
        return new_s, new_a, fixed_lines, partial


def _resolve_targets(stmts, addrs, stmt_addr=None) -> list[Any]:
    """Replace ("addr", a) jump targets with statement indices. (Synthesized statements
    like Dim carry a None address and are never jump targets.)

    A target inside a SUB/DEF FN body resolves to ir.BodyLine(top_idx, phys):
    emit0 numbers that body physical line. Body statement addresses ride in
    `stmt_addr` (id(stmt) -> addr, captured at fold time). phys is the 1-based
    physical-line offset from the header, so it is only computable while every
    preceding body statement renders as one physical line -- anything else
    raises loudly (only the witnessed flat-body shape, t1_subgsb). A nested
    single-arm, no-else IfBlock (itself only produced when ITS OWN body has
    an addressable target -- see `_fold_body`'s "second leg") is the one
    exception: recurse into it, since its header line still occupies exactly
    one physical line and its own body continues the SAME top_idx's phys
    count (a numbered nested-IF interior two block levels deep, wild
    inv87.exe -- gap 51 only reached one level)."""
    index: dict[Any, Any] = {a: i for i, a in enumerate(addrs) if a is not None}

    if stmt_addr:

        def map_body(top_idx, body, phys):
            multi = False
            for b in body:
                a = stmt_addr.get(id(b))
                if a is not None and a not in index:
                    if multi:
                        raise ValueError(
                            f"jump target {a:#x}: body line not addressable past "
                            "a multi-line statement"
                        )
                    index[a] = ir.BodyLine(top_idx, phys)
                if isinstance(b, ir.IfBlock):
                    # Header (already counted as `phys` above) + body
                    # (recursed, exact) + END IF -- a fully-accounted block, so
                    # flat counting can safely continue past it (unlike the
                    # generic multi-line cases below, whose width isn't known).
                    # ELSEIF/ELSE arms extend the same accounting: emit0.py
                    # renders one header line per arm, then that arm's body,
                    # then an optional "ELSE" line + body, then "END IF"
                    # (probe t1_dblhooksub, a block IF/ELSEIF/ELSE inside a SUB
                    # body whose first post-block statement is a jump target).
                    for _cond, arm_body in b.arms:
                        phys = map_body(top_idx, arm_body, phys + 1)
                    if b.else_body is not None:
                        phys = map_body(top_idx, b.else_body, phys + 1)
                    phys += 1  # "END IF"
                elif isinstance(b, ir.SelectCase):
                    # Fully accounted like the single-arm IfBlock above:
                    # emit0.py's own SelectCase rendering is a deterministic
                    # "SELECT CASE" line + per-arm ("CASE guards" line +
                    # body) + optional ("CASE ELSE" line + body) + "END
                    # SELECT" line, so flat counting can safely continue
                    # past it too (wild rsltest.exe: TBMENU.INC's `select
                    # case ans$ ... end select`, whose first post-arm
                    # statement is itself a jump target).
                    phys += 1  # "SELECT CASE selector"
                    for arm in b.arms:
                        phys = map_body(top_idx, arm.body, phys + 1)
                    if b.case_else is not None:
                        phys = map_body(top_idx, b.case_else, phys + 1)
                    phys += 1  # "END SELECT"
                elif isinstance(b, (ir.IfBlock, ir.SubDef, ir.DefFn)):
                    multi = True
                    phys += 1
                else:
                    phys += 1
            return phys

        for i, s in enumerate(stmts):
            if isinstance(s, ir.IfBlock):
                # A single-arm block IF's interior is addressable when the
                # source numbered the line (t1_blkgoto): phys k+1 counts from
                # the IF header exactly like a SUB body counts from SUB.
                # Multi-arm/ELSE interiors are unwitnessed -- their targets
                # stay unresolved and raise below.
                body = (
                    s.arms[0][1]
                    if len(s.arms) == 1 and s.else_body is None
                    else ()
                )
            else:
                body = (
                    s.body
                    if isinstance(s, ir.SubDef)
                    or (isinstance(s, ir.DefFn) and s.is_block)
                    else ()
                )
            map_body(i, body, 1)

    def fix(s):
        if isinstance(s, (ir.Goto, ir.IfGoto, ir.Gosub)) or (
            isinstance(s, ir.Return) and s.target is not None
        ):
            tag, a = s.target
            assert tag == "addr"
            if a not in index:
                raise ValueError(f"jump target {a:#x} is not a statement start")
            if isinstance(s, ir.Goto):
                return ir.Goto(index[a])
            if isinstance(s, ir.Gosub):
                return ir.Gosub(index[a])
            if isinstance(s, ir.Return):
                return ir.Return(index[a])
            return ir.IfGoto(s.cond, index[a])
        if isinstance(s, (ir.OnGoto, ir.OnGosub)):
            new = []
            for tag, a in s.targets:
                assert tag == "addr"
                if a not in index:
                    raise ValueError(f"jump target {a:#x} is not a statement start")
                new.append(index[a])
            cls = ir.OnGoto if isinstance(s, ir.OnGoto) else ir.OnGosub
            return cls(s.selector, tuple(new))
        if isinstance(s, (ir.OnError, ir.Resume)) and s.target is not None:
            tag, a = s.target
            assert tag == "addr"
            if a not in index:
                raise ValueError(f"jump target {a:#x} is not a statement start")
            if isinstance(s, ir.OnError):
                return ir.OnError(index[a])
            return ir.Resume(target=index[a])
        if isinstance(s, ir.OnTrap):
            tag, a = s.target
            assert tag == "addr"
            if a not in index:
                raise ValueError(f"jump target {a:#x} is not a statement start")
            return ir.OnTrap(s.event, s.n, index[a])
        if isinstance(s, ir.IfInline):
            return ir.IfInline(s.cond, tuple(fix(b) for b in s.body))
        if isinstance(s, ir.IfBlock):
            arms = tuple((c, tuple(fix(b) for b in body)) for c, body in s.arms)
            else_body = (
                None if s.else_body is None else tuple(fix(b) for b in s.else_body)
            )
            return ir.IfBlock(arms, else_body)
        if isinstance(s, ir.SelectCase):
            arms = tuple(
                ir.CaseArm(arm.guards, tuple(fix(b) for b in arm.body))
                for arm in s.arms
            )
            ce = None if s.case_else is None else tuple(fix(b) for b in s.case_else)
            return ir.SelectCase(s.selector, arms, ce)
        if isinstance(s, ir.SubDef):
            return ir.SubDef(s.name, s.params, tuple(fix(b) for b in s.body))
        if isinstance(s, ir.DefFn) and s.is_block:
            return ir.DefFn(s.name, s.params, tuple(fix(b) for b in s.body), True)
        return s

    return [fix(s) for s in stmts]
