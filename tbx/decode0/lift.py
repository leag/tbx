"""Structured-control-flow lifting: FOR/DO/WHILE/IF folds and target resolution."""

from __future__ import annotations
from typing import Any

from tbx import ir
from tbx.decode0.const import _JCC_RELOP_TRUE, _NEGATE_REL
from tbx.decode0.rename import _slot


def _is_for_header(stmts, vdisp) -> bool:
    """Three trailing assignments to consecutive slots limit=v-4, step=v-8, then init to v."""
    if len(stmts) < 3 or not all(isinstance(s, ir.Assign) for s in stmts[-3:]):
        return False
    lim_s, stp_s, init_s = stmts[-3:]
    if not all(isinstance(s.target, ir.Var) for s in (lim_s, stp_s, init_s)):
        return False
    if any(s.target.name.endswith("$") for s in (lim_s, stp_s, init_s)):
        # A FOR variable is never a string, and consecutive string slots are
        # ALSO 4 bytes apart, so the v-4/v-8 probe below could false-positive
        # on three trailing string assigns before a GOTO (witnessed t1_strgoto
        # / wild inv87.exe -- vdisp can't even parse the "$" placeholder).
        return False
    v = vdisp(init_s.target)
    return vdisp(lim_s.target) == v - 4 and vdisp(stp_s.target) == v - 8


def _lift_next(ops, k, fors, stmts, addrs, exit_folds) -> int:
    """Consume the NEXT template at ops[k] (a testw at the open FOR's test address):
    testw [step+2],8000h; 74 +3; e9 NEG; FLD lim; FCOMP v; fstsw; <73 BODY>; e9 EXIT;
    NEG: FLD lim; FCOMP v; fstsw; <76 BODY>.  Each <jcc BODY> is short, or the long
    form `jcc-inverse +3; e9 BODY` when the body is out of short reach."""
    f = fors[-1]
    v, lim, stp = f["v"], f["v"] - 4, f["v"] - 8

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
        if o[1] == "jcc" and o[2] == cc and o[3] == f["body"]:
            return i + 1
        if (
            o[1] == "jcc"
            and o[2] == inv
            and o[3] == o[0] + 5
            and i + 1 < len(ops)
            and ops[i + 1][1] == "jmp"
            and ops[i + 1][2] == f["body"]
        ):
            return i + 2
        raise ValueError(
            f"NEXT template mismatch at {o[0]:#x}: {o} != jcc {cc:#x} BODY"
        )

    i = expect(k, [("testw", stp + 2, 0x8000), ("jcc", 0x74, None), ("jmp", None)])
    i = expect(i, [("fld", lim), ("fcomp", v), ("fstsw",)])
    i = jcc_body(i, 0x73, 0x72)
    i = expect(i, [("jmp", None)])  # EXIT
    neg_start = i
    i = expect(i, [("fld", lim), ("fcomp", v), ("fstsw",)])
    i = jcc_body(i, 0x76, 0x77)
    if ops[k + 2][2] != ops[neg_start][0]:  # e9 NEG must land on the second FLD
        raise ValueError("NEXT template: bad negative-path target")
    # the increment `v = v + step` was lifted as the preceding Assign -- fold it in
    inc = stmts[-1]
    slot_v, slot_s = _slot(v), _slot(stp)
    if inc not in (
        ir.Assign(ir.Var(slot_v), ir.BinOp("+", ir.Var(slot_v), ir.Var(slot_s))),
        ir.Assign(ir.Var(slot_v), ir.BinOp("+", ir.Var(slot_s), ir.Var(slot_v))),
    ):
        raise ValueError(f"NEXT increment mismatch: {inc}")
    a = addrs[-1]
    del stmts[-1], addrs[-1]
    stmts.append(ir.NextStmt(ir.Var(slot_v)))
    addrs.append(a)
    fors.pop()
    # EXIT FOR: a GOTO to the post-NEXT address (the op after this template) is an exit;
    # the conditional that skips it jumps to the NEXT (this stmt's addr). Fold at epilogue.
    if i < len(ops):
        exit_folds.append((ir.ExitFor(), a, ops[i][0]))
    return i


def _match_bool_term1(ops, k):
    """ops[k] = movax FFFF with a pending compare. Detect a compound-IF first
    term: the materialization header whose closing jmp short-circuits INTO the
    second term's tail -- AND (jnz dispatch) jumps to the commit after `and ax,bx`,
    OR (jz) jumps to the tail's `or ax,ax` with ax still 0FFFFh. Returns "AND"/"OR"
    or None (then it's a WHILE header; the address equality dishambiguates exactly)."""
    if [o[1] for o in ops[k : k + 6]] != [
        "movax",
        "jcc",
        "incax",
        "orax",
        "jcc",
        "jmp",
    ]:
        return None
    if (
        ops[k + 1][3] != ops[k + 3][0]
        or ops[k + 1][2] not in _JCC_RELOP_TRUE
        or ops[k + 4][3] != ops[k + 5][0] + 3
    ):
        return None
    pol, sc = ops[k + 4][2], ops[k + 5][2]
    comb = {0x75: ("andaxbx", "AND"), 0x74: ("orax", "OR")}.get(pol)
    if comb is None:
        return None
    for j in range(k + 6, min(k + 30, len(ops) - 3)):
        if (
            ops[j][1] == "movax"
            and ops[j][2] == 0xFFFF
            and [o[1] for o in ops[j + 1 : j + 4]] == ["jcc", "incax", comb[0]]
        ):
            tail_comb = ops[j + 3]
            if sc == tail_comb[0] + (2 if comb[1] == "AND" else 0):
                return comb[1]
    return None


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


def _lift_bool_tail(ops, k, pend_cmp, pb, put, whiles, ifs, stmts, flush):
    """Consume the compound-IF second term at ops[k] (movax FFFF): dispatch 74 =
    THEN-line IfGoto; dispatch 75 = compound WHILE (jmps-back present)
    or inline-IF body. A 3+-term chain (witnessed t1_and3) cascades: each MID
    segment's dispatch jmp short-circuits into the NEXT segment's fold template
    (comb addr + the same +2/+0 AND/OR delta the first-term match uses) instead
    of exiting -- fold the condition and keep the compound open. Returns
    (next op index, still-open pend_bool or None)."""
    comb = "andaxbx" if pb["op"] == "AND" else "orax"
    if [o[1] for o in ops[k : k + 6]] != [
        "movax",
        "jcc",
        "incax",
        comb,
        "jcc",
        "jmp",
    ] or ops[k][2] != 0xFFFF:
        raise ValueError(f"compound-IF tail mismatch at {ops[k][0]:#x}")
    m_jcc, f_jcc, f_jmp = ops[k + 1], ops[k + 4], ops[k + 5]
    if m_jcc[3] != ops[k + 3][0] or m_jcc[2] not in _JCC_RELOP_TRUE:
        raise ValueError(f"compound-IF tail: bad Jcc skip at {m_jcc[0]:#x}")
    if f_jcc[2] not in (0x74, 0x75) or f_jcc[3] != f_jmp[0] + 3:
        raise ValueError(f"compound-IF tail: bad dispatch pair at {f_jcc[0]:#x}")
    delta = 2 if pb["op"] == "AND" else 0
    if pb["sc"] != ops[k + 3][0] + delta:
        raise ValueError(
            f"compound-IF: short-circuit target mismatch at {ops[k][0]:#x}"
        )
    r2 = ir.RelOp(_JCC_RELOP_TRUE[m_jcc[2]], *pend_cmp)
    cond = ir.LogOp(pb["op"], pb["r1"], r2)
    for j in range(k + 6, min(k + 36, len(ops) - 3)):
        if (
            ops[j][1] == "movax"
            and ops[j][2] == 0xFFFF
            and [o[1] for o in ops[j + 1 : j + 4]] == ["jcc", "incax", comb]
            and f_jmp[2] == ops[j + 3][0] + delta
        ):  # mid segment: chain continues at ops[j]'s fold
            return k + 6, {
                "r1": cond,
                "op": pb["op"],
                "sc": f_jmp[2],
                "start": pb["start"],
            }
    if f_jcc[2] == 0x74:
        put(ir.IfGoto(cond, ("addr", f_jmp[2])), pb["start"])
    elif _has_jmps_back(ops, f_jmp[2], pb["start"]):
        put(ir.While(cond), pb["start"])
        whiles.append({"test": pb["start"], "exit": f_jmp[2]})
    else:
        flush()
        ifs.append(
            {"target": f_jmp[2], "cond": cond, "start": pb["start"], "idx": len(stmts)}
        )
    return k + 6, None


def _lift_do_tail(ops, k, pend_cmp, stmts, addrs, put, cur):
    """Tail-test DO ... LOOP WHILE/UNTIL: mov ax,0FFFF; Jcc(R) +1; inc ax; or ax,ax;
    <cc BACKWARD> where BACKWARD targets an earlier statement (the loop body start) --
    no trailing e9 (the conditional jcc IS the back-edge). Splice a bare `DO` before
    the body and emit `LOOP WHILE/UNTIL cond` here. cc 75 = continue-if-true = WHILE;
    cc 74 = continue-if-false = UNTIL. Returns the next op index, or None if no match.
    """
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
    put(ir.Loop(kind, cond), cur)
    return k + len(want)


def _lift_bool_do_tail(ops, k, pend_cmp, pb, stmts, addrs, put):
    """Compound-IF second term ending in a tail-test DO ... LOOP WHILE/UNTIL:
    same shape as `_lift_do_tail` (materialization's Jcc IS the backward
    loop edge, no trailing jmp), except the combining op at index 3 is the
    compound's AND/OR fold (from `pb`) rather than a bare self-test `or ax,ax`.
    Returns the next op index, or None if no match (caller falls back to
    `_lift_bool_tail`'s dispatch-jcc+jmp shape)."""
    comb = "andaxbx" if pb["op"] == "AND" else "orax"
    want = ["movax", "jcc", "incax", comb, "jcc"]
    if k + len(want) > len(ops) or [o[1] for o in ops[k : k + len(want)]] != want:
        return None
    m_jcc, back_jcc = ops[k + 1], ops[k + 4]
    if m_jcc[3] != ops[k + 3][0] or m_jcc[2] not in _JCC_RELOP_TRUE:
        return None
    if pb["sc"] != ops[k + 3][0] + (2 if pb["op"] == "AND" else 0):
        return None
    back = back_jcc[3]
    if back_jcc[2] not in (0x74, 0x75) or back >= ops[k][0] or back not in addrs:
        return None
    r2 = ir.RelOp(_JCC_RELOP_TRUE[m_jcc[2]], *pend_cmp)
    cond = ir.LogOp(pb["op"], pb["r1"], r2)
    kind = "WHILE" if back_jcc[2] == 0x75 else "UNTIL"
    idx = addrs.index(back)  # splice `DO` before the body start
    stmts.insert(idx, ir.Do(None))
    addrs.insert(idx, None)
    put(ir.Loop(kind, cond), pb["start"])
    return k + len(want)


def _lift_while(ops, k, pend_cmp, whiles, dos, ifs, stmts, put, flush, cur) -> int:
    """Consume the materialized loop test at ops[k] (mov ax,0FFFF):
    Jcc(R) +1; inc ax; or ax,ax; <cc> +3; e9 EXIT. With a loop-back before
    EXIT it is a head-test loop -- `DO WHILE cond` (cc 75, continue-if-true) or
    `DO UNTIL cond` (cc 74, continue-if-false); without one it is an inline-IF body
    skip (cc 75 only)."""
    want = ["movax", "jcc", "incax", "orax", "jcc", "jmp"]
    if k + len(want) > len(ops) or [o[1] for o in ops[k : k + len(want)]] != want:
        raise ValueError(f"materialization template mismatch at {ops[k][0]:#x}")
    m_jcc, exit_jcc, exit_jmp = ops[k + 1], ops[k + 4], ops[k + 5]
    if m_jcc[3] != ops[k + 3][0]:  # Jcc +1 skips exactly the inc ax
        raise ValueError("materialization: bad Jcc skip")
    if m_jcc[2] not in _JCC_RELOP_TRUE:
        raise ValueError(f"unhandled materialization jcc {m_jcc[2]:02x}")
    if exit_jcc[2] not in (0x74, 0x75) or exit_jcc[3] != exit_jmp[0] + 3:
        raise ValueError("DO/WHILE: bad exit pair")
    cond = ir.RelOp(_JCC_RELOP_TRUE[m_jcc[2]], *pend_cmp)
    if _has_jmps_back(ops, exit_jmp[2], cur):  # head-test DO loop
        kind = "WHILE" if exit_jcc[2] == 0x75 else "UNTIL"
        put(ir.Do(kind, cond), cur)
        dos.append({"test": cur, "exit": exit_jmp[2]})
    elif exit_jcc[2] == 0x75:  # inline-IF
        flush()
        ifs.append(
            {"target": exit_jmp[2], "cond": cond, "start": cur, "idx": len(stmts)}
        )
    else:
        raise ValueError(f"unhandled materialized test at {ops[k][0]:#x}")
    return k + len(want)


def _inline_safe(body) -> bool:
    """A THEN/ELSE body renders on one line only if no nested IF precedes the last
    statement (else a trailing statement would bind to the inner IF -- it must block).
    """
    return not any(isinstance(b, (ir.IfInline, ir.IfBlock)) for b in body[:-1])


def _fold_body(body):
    """Recursively block-fold nested non-inline-safe IFs within an arm/else body
    (bodies carry no Goto-else marker; only the rendering split applies here)."""
    out = []
    for b in body:
        if isinstance(b, ir.IfInline) and not _inline_safe(b.body):
            out.append(ir.IfBlock(((b.cond, _fold_body(b.body)),), None))
        else:
            out.append(b)
    return tuple(out)


def _apply_exit_folds(stmts, addrs, exit_folds):
    """EXIT FOR/LOOP/SUB/DEF folds: rewrite the early-exit GOTO to the
    loop/proc exit, then fold `IF c THEN <skip>` + EXIT into `IF negate(c) THEN EXIT`.
    """
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


def _jump_targets(stmts) -> frozenset[int]:
    """Every address referenced as a jump target anywhere in the statement
    tree (Goto/IfGoto/Gosub, ON GOTO/GOSUB lists, ON ERROR/RESUME/ON-trap),
    including inside already-lifted IfInline bodies."""
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

    for s in stmts:
        walk(s)
    return frozenset(out)


def _fold_if(stmts, addrs, bound=None, targets=frozenset()):
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
                arms = [(s.cond, _fold_body(s.body[:-1]))]
                else_s, _ = _fold_if(
                    stmts[i + 1 : end_idx],
                    addrs[i + 1 : end_idx],
                    bound=end,
                    targets=targets,
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
        if isinstance(s, ir.IfInline) and not _inline_safe(s.body):
            out_s.append(ir.IfBlock(((s.cond, _fold_body(s.body)),), None))
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
    raises loudly (only the witnessed flat-body shape, t1_subgsb)."""
    index: dict[Any, Any] = {a: i for i, a in enumerate(addrs) if a is not None}
    if stmt_addr:
        for i, s in enumerate(stmts):
            body = (
                s.body
                if isinstance(s, ir.SubDef)
                or (isinstance(s, ir.DefFn) and s.is_block)
                else ()
            )
            multi = False
            for k, b in enumerate(body):
                a = stmt_addr.get(id(b))
                if a is not None and a not in index:
                    if multi:
                        raise ValueError(
                            f"jump target {a:#x}: body line not addressable past "
                            "a multi-line statement"
                        )
                    index[a] = ir.BodyLine(i, k + 1)
                if isinstance(b, (ir.IfBlock, ir.SelectCase, ir.SubDef, ir.DefFn)):
                    multi = True

    def fix(s):
        if isinstance(s, (ir.Goto, ir.IfGoto, ir.Gosub)):
            tag, a = s.target
            assert tag == "addr"
            if a not in index:
                raise ValueError(f"jump target {a:#x} is not a statement start")
            if isinstance(s, ir.Goto):
                return ir.Goto(index[a])
            if isinstance(s, ir.Gosub):
                return ir.Gosub(index[a])
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
