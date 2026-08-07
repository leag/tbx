"""SELECT CASE recognizer: a state machine over the open `cases` frames.

`step(state)` is called once at the top of the decode loop; it returns True
when it consumed the current op(s) and the loop should `continue`, False to
let the op fall through to normal dispatch. All helpers thread the shared
:class:`~tbx.decode0.core.DecodeState` explicitly.
"""

from __future__ import annotations

from tbx import ir
from tbx.decode0.statement_log import editing
from tbx.decode0.const import _IS_RELOP, VAR_BASE
from tbx.decode0.frames import SelectFrame
from tbx.decode0.lift import _fold_if, _jump_targets, _negate_cond, _target_counts


def _kind_at(state, i):
    img = state.image
    return img.ops[i][1] if 0 <= i < len(img.ops) else None


def _is_is_mat_at(state, c):  # IS-relational materialized-boolean compare idiom
    return (
        _kind_at(state, c) == "fcomp"
        and _kind_at(state, c + 1) == "fstsw"
        and _kind_at(state, c + 2) == "movax"
        and _kind_at(state, c + 3) == "jcc"
        and _kind_at(state, c + 4) == "incax"
        and _kind_at(state, c + 5) == "movmem_ax"
        and _kind_at(state, c + 6) == "fild"
        and _kind_at(state, c + 7) == "fcomp64"
    )


def _skip_hooks(state, i):
    """The first index at or after `i` that is not an event-trap poll stamp."""
    while _kind_at(state, i) == "trap_hook":
        i += 1
    return i


def _is_arm_header_at(state, i):
    return _kind_at(state, i) in ("fldz", "fld1", "fild", "fld") and (
        _kind_at(state, i + 1) == "fcomp64" or _is_is_mat_at(state, i + 1)
    )


def _arm_temp_at(state, i):
    img = state.image
    if _kind_at(state, i + 1) == "fcomp64":
        return img.ops[i + 1][2]
    if _kind_at(state, i + 1) == "fcomp" and _kind_at(state, i + 8) == "fcomp64":
        return img.ops[i + 8][2]
    return None


def _is_str_arm_header_at(state, i, temp):
    img = state.image
    return (
        _kind_at(state, i) == "movsi"
        and _kind_at(state, i + 1) == "rt"
        and img.ops[i + 1][2] == 0x9C
        and _kind_at(state, i + 2) == "movsi"
        and img.ops[i + 2][2] == temp
        and _kind_at(state, i + 3) == "rt"
        and img.ops[i + 3][2] == 0x9C
        and _kind_at(state, i + 4) == "strcmp"
    )


def _is_str_arm_header_chr_at(state, i, temp):
    # A CHR$(n) guard (wild rsltest.exe: `case chr$(72),chr$(75),"-",...`,
    # mixing computed and bare-literal guards in one arm list) computes the
    # value at the guard site instead of loading an existing descriptor --
    # movax n; strfn CHR$ where the bare form's leading movsi/rt pair sits.
    img = state.image
    return (
        _kind_at(state, i) == "movax"
        and _kind_at(state, i + 1) == "strfn"
        and img.ops[i + 1][2] == "CHR$"
        and _kind_at(state, i + 2) == "movsi"
        and img.ops[i + 2][2] == temp
        and _kind_at(state, i + 3) == "rt"
        and img.ops[i + 3][2] == 0x9C
        and _kind_at(state, i + 4) == "strcmp"
    )


def _str_guard_arm(state, k, guard):
    """Shared tail for a matched string-arm guard header (movsi/movax..
    strcmp at k..k+4, jcc at k+5, jmp at k+6). Mirrors the numeric arm's
    own cc==0x75(JNE, value-list non-final)/cc==0x74(JE, final/only) split
    exactly -- structural position alone can't distinguish them (a
    non-final guard's mismatch branch and a final guard's match branch
    both land on the immediately-following op when the compiler lays
    guards out contiguously, witnessed on both cc's in wild zz_sc5/
    rsltest.exe), so the cc value is the only reliable signal, same as
    the numeric arm (wild rsltest.exe: `case chr$(72),chr$(75),"-","8",
    "4"` needs the non-final path; every single-guard CASE calibrated
    before this only ever exercised the final path)."""
    i, c = state.image, state.control
    jcc = i.ops[k + 5]
    c.cases[-1].cur_guards.append(ir.CaseValue(guard))
    if jcc[2] in (0x72, 0x73, 0x75, 0x76, 0x77):  # range/non-final guard
        state.seek(k + 7)
        c.cur = None
        return True
    if jcc[2] == 0x74:  # JE: literal final/only guard -> begin body
        next_test = i.ops[k + 6][2]
        _begin_body(state, k + 7, next_test)
        return True
    raise ValueError(
        f"SELECT CASE string arm: unexpected jcc {jcc[2]:02x} at {i.ops[k][0]:#x}"
    )


def _op_index_at(state, a):
    img = state.image
    for i, o in enumerate(img.ops):
        if o[0] == a:
            return i
    return None


def _begin_body(state, body_i, next_test):
    img, c, o = state.image, state.control, state.output
    i = body_i
    while i < len(img.ops) and img.ops[i][0] < next_test:
        i += 1
    if i == body_i:
        # Empty CASE arms are emitted by TB when adjacent guards share the
        # same fall-through point (wild ifi/bmaster).  There is no statement
        # region to fold; record a zero-width arm and let ``step`` append the
        # empty CaseArm when it reaches the next guard/END SELECT.
        fr = c.cases[-1]
        fr.next_test = next_test
        fr.body_idx = len(o.stmts)
        fr.body_jmp = next_test
        fr.body_seq = state.region(
            "case_arm", start=next_test, end=next_test,
            detail=tuple(fr.cur_guards),
        ).seq
        state.seek(body_i)
        c.cur = None
        return
    last_jmp_target = img.ops[i - 1][2] if img.ops[i - 1][1] == "jmp" else None
    fr = c.cases[-1]
    fr.next_test = next_test
    fr.body_idx = len(o.stmts)
    if last_jmp_target is not None:
        fr.body_jmp = img.ops[i - 1][0]
        if fr.end_select == 0:
            fr.end_select = last_jmp_target
    else:  # flow-through final arm (no trailing jmp)
        if fr.end_select == 0 or next_test != fr.end_select:
            # Wild SELECT layouts can fall through directly into the next
            # arm's test without the canonical closing jump. Use that test as
            # the arm boundary so later arms remain decodable.
            fr.end_select = next_test
        fr.body_jmp = next_test
    # The body's extent is known here and nowhere earlier: where it starts, and
    # the arm-close jmp it runs to. Recording it is what lets the snapshot read
    # its own region back out of the log instead of off this frame.
    fr.body_seq = state.region(
        "case_arm",
        start=img.ops[body_i][0],
        end=fr.body_jmp,
        # Every guard of this arm has been matched by now -- the body only
        # begins once the last one has -- so this is where the arm's whole
        # recognition is known at once.
        detail=tuple(fr.cur_guards),
    ).seq
    state.seek(body_i)
    c.cur = None


def _fold_arm(state, frame, merge):
    """Block-fold the arm (or CASE ELSE) body and return it, addresses retained.

    Where the body begins comes from the record: `frame.body_seq` is the
    region event `_begin_body` wrote, and the list length at that event is the
    position. `frame.body_idx` is kept for the snapshot itself, not as a
    agree -- the same arrangement the inline-IF fold uses, and the same one
    Chapter 7 removes.

    An arm body is snapshotted here and never revisited by the top-level
    `_fold_if` pass -- exactly the situation `core.py`'s `proc_ret` already
    handles for a SUB body ("it has to happen now or its IfInlines stay inline
    and the else-skip Goto survives as a spurious statement"). Arms had no such
    pass at all, so a block IF inside a CASE arm kept its skip-Goto and lost its
    ELSE.

    `merge` is the arm's own end address: a nested IF/ELSE whose arms all fall
    through to the end of the arm skips straight to the arm-close jmp, so that
    address -- not any statement -- is the region terminator `_fold_if` needs as
    `bound`.

    Witnessed by wild tbd73.exe, TBW73.INC:658-670, `SUB Makelmenu`'s
    `CASE CHR$(80)`: three nested block IFs (one with an ELSE) all end at the
    arm, so three skips converge on the arm's trailing `jmp END SELECT`
    (`jump target 0xd0ba is not a statement start`). Fixture t1_selarmblockif.
    """
    c, o = state.control, state.output
    # An inline IF closing this arm skips to the arm-close address, and
    # `select_case.step` runs BEFORE the dispatch loop's own close point -- so
    # close those frames here, or the arm folds away with one still open
    # (TBW73.INC:716, via DecodeState.open_tail_if). `close_ifs` only queues
    # the region now, so drain immediately after: the arm must not be
    # snapshotted around a region still waiting to fold.
    state.close_ifs(merge)
    body_idx = state.frame_start(frame.body_seq)
    state.drain_folds(body_idx)
    stmts, addrs = _fold_if(
        o.stmts[body_idx:],
        o.addrs[body_idx:],
        bound=merge,
        targets=_jump_targets(o.stmts),
        stmt_addr=o.stmt_addr,
        block_ifs=c.block_if_addrs,
    )
    stmts, addrs = _fold_arm_ifgoto_else(stmts, addrs, merge, _target_counts(o.stmts))
    o.stmts[body_idx:], o.addrs[body_idx:] = stmts, addrs
    body = tuple(o.stmts[body_idx:])
    _keep_addrs(state, body, body_idx)
    return body


def _addr_target(t):
    """The address an unresolved `("addr", a)` target names, else None."""
    return t[1] if isinstance(t, tuple) and t and t[0] == "addr" else None


def _fold_arm_ifgoto_else(stmts, addrs, merge, counts):
    """Fold single-line IFs that `_fold_if` cannot see, inside a CASE arm.

    A simple condition canonicalizes to `ir.IfGoto`, never to the `ir.IfInline`
    `_fold_if` matches on, so `IF c THEN x [ELSE y]` reaches here as a
    conditional GOTO plus loose statements:

        IF c THEN x            IfGoto(NOT c, ->arm end)   <then...>
        IF c THEN x ELSE y     IfGoto(NOT c, ->E)  <then...>  Goto(->arm end)
                               E: <else...>

    At top level both spellings are fine -- they emit as numbered lines and
    recompile byte-for-byte, which is why this must NOT run there (t1_ifgoto).
    In an arm they cannot be spelled: the skip targets the arm's own end, which
    is the arm-close jmp and owns no statement, so the address never resolves
    (`jump target 0x873e is not a statement start`).

    Folding to `ir.IfBlock` would be wrong rather than merely ugly -- over a
    simple condition the block spelling compiles to different bytes -- so this
    reproduces the source's own single-line form via `IfInline.else_body`, with
    the condition negated back into its source sense.

    An ELSE run is folded recursively, which is what recovers a chained
    `IF a THEN x ELSE IF b THEN y ELSE z`: every arm of the chain skips to the
    same arm end, so `merge` stays fixed all the way down.

    Only a branch to the arm end is rewritten. An IfGoto naming a real
    statement inside the arm already resolves and already round-trips as a
    numbered line, so it is left exactly as it is.
    """
    local = _target_counts(stmts)
    if counts.get(merge, 0) != local.get(merge, 0):
        # Something outside this arm jumps to its end; the arm-close address is
        # not ours alone to consume.
        return stmts, addrs
    return _fold_region(stmts, addrs, merge, counts)


def _unreferenced(addrs, counts) -> bool:
    """No statement anywhere names one of these addresses.

    A run about to be swallowed into an inline body stops being addressable, so
    it may not hold a jump target -- the same rule `_fold_if` applies to an ELSE
    region, and the reason a source that really did spell numbered lines is left
    alone.
    """
    return not any(counts.get(a, 0) for a in addrs if a is not None)


def _fold_ifgoto_then(stmts, addrs, index, merge, counts):
    if index + 1 >= len(stmts) or not _unreferenced(addrs[index + 1 :], counts):
        return None
    statement = stmts[index]
    return ir.IfInline(_negate_cond(statement.cond), tuple(stmts[index + 1 :]), None)


def _fold_ifgoto_else(stmts, addrs, index, target, merge, counts):
    end = next(
        (position for position in range(index + 1, len(stmts)) if addrs[position] == target),
        None,
    )
    if end is None or end - 1 <= index:
        return None
    skip = stmts[end - 1]
    if not isinstance(skip, ir.Goto) or _addr_target(skip.target) != merge:
        return None
    if counts.get(target, 0) != 1 or not _unreferenced(addrs[index + 1 : end - 1], counts):
        return None
    else_body, _ = _fold_region(stmts[end:], addrs[end:], merge, counts)
    statement = stmts[index]
    return ir.IfInline(
        _negate_cond(statement.cond),
        tuple(stmts[index + 1 : end - 1]),
        tuple(else_body),
    )


def _fold_region(stmts, addrs, merge, counts):
    out_s, out_a = [], []
    i = 0
    while i < len(stmts):
        s, a = stmts[i], addrs[i]
        target = _addr_target(s.target) if isinstance(s, ir.IfGoto) else None
        node = None
        if target is not None and a is not None and target > a:
            node = (
                _fold_ifgoto_then(stmts, addrs, i, merge, counts)
                if target == merge
                else _fold_ifgoto_else(stmts, addrs, i, target, merge, counts)
            )
        if node is None:
            out_s.append(s)
            out_a.append(a)
            i += 1
            continue
        out_s.append(node)
        out_a.append(a)
        i = len(stmts)  # the fold reaches the arm end by construction
    return out_s, out_a


def _keep_addrs(state, body, body_idx) -> None:
    """Carry an arm/CASE-ELSE body's statement addresses into `o.stmt_addr`
    before the snapshot deletes them from `o.addrs`.

    Folding an arm moves its statements off the flat list, so their addresses
    vanish with it -- exactly what `core.py` already guards against at
    `proc_ret` for a SUB body (`stmt_addr[id(st)] = ad`, the t1_subgsb path).
    Without it a jump landing INSIDE a CASE arm can never resolve, even though
    `_resolve_targets`'s `map_body` walks SelectCase arms and knows how to
    number them.

    Witnessed by wild tbd73.exe, TBW73.INC:486-487, inside
    `SELECT CASE ans1$ / CASE CHR$(72)`:

        DECR curntpos
        IF curntpos < 1 THEN curntpos = itemcount
        WHILE MID$(liveitem$,curntpos,1) = "0"

    The IF normalizes to `IF curntpos >= 1 THEN <line>` whose target is the
    WHILE header two statements later, in the SAME arm
    (`jump target 0xba9f is not a statement start`). Fixture t1_selarmtarget.
    """
    o = state.output
    for st, ad in zip(body, o.addrs[body_idx:]):
        if ad is not None:
            o.stmt_addr.claim(st, ad)


def step(state):
    with editing(state.output.stmts, "select_case"):
        i, e, c, o = state.image, state.expr, state.control, state.output
        op = i.ops[c.k]
        addr, kind = op[0], op[1]
        # (1) END SELECT: every arm body has jumped here -> emit the statement.
        if (
            c.cases
            and c.cases[-1].body_jmp is None
            and addr == c.cases[-1].end_select
        ):
            state.flush_pending()
            fr = c.cases.pop()
            case_else = None
            if fr.in_else:
                case_else = _fold_arm(state, fr, addr)
                del o.stmts[fr.body_idx :], o.addrs[fr.body_idx :]
                if not case_else:
                    # An EMPTY else region means the source had no CASE ELSE at all:
                    # `in_else` is set whenever the op after the last arm's jmp is
                    # not another arm header, which also covers landing straight on
                    # the END SELECT. Emitting `CASE ELSE` with nothing under it is
                    # not byte-free -- it was the ENTIRE 213-byte round-trip
                    # mismatch on the two-arm string SELECT inside TBW73.INC:510-514
                    # (fixture t1_ifblockselect: dropping just those two emitted
                    # lines makes the recompile byte-identical).
                    #
                    # This maps empty -> None, so a source that really did spell an
                    # empty `CASE ELSE` would come back without it. That spelling is
                    # unwitnessed and would compile to different bytes, so it would
                    # surface as a round-trip mismatch rather than pass silently.
                    case_else = None
            # The construct's own extent, recorded here because this is the one
            # point where both ends are known: a SELECT header cannot record it,
            # since the END SELECT address is not known until an arm names it
            # (which is why the header's branch event carries `target=None`).
            state.region(
                "select", start=fr.start, end=addr, detail=fr.selector
            )
            o.stmts.append(ir.SelectCase(fr.selector, tuple(fr.arms), case_else))
            o.addrs.append(fr.start)
            c.cur = None
            return False  # process the op at END SELECT normally
        # (2) Arm body close: the current op is this arm's trailing `jmp END_SELECT`.
        if c.cases and c.cases[-1].body_jmp == addr:
            state.flush_pending()
            fr = c.cases[-1]
            body = _fold_arm(state, fr, addr)
            del o.stmts[fr.body_idx :], o.addrs[fr.body_idx :]
            fr.arms.append(ir.CaseArm(tuple(fr.cur_guards), body))
            fr.cur_guards = []
            fr.body_jmp = None
            if kind != "jmp":  # flow-through final arm closes AT END SELECT
                return True
            state.advance()  # consume the trailing jmp
            c.cur = None
            nxt_is_arm = (
                _is_str_arm_header_at(state, c.k, fr.temp)
                if fr.is_string
                else _is_arm_header_at(state, c.k)
            )
            if fr.next_test == fr.end_select:
                pass  # no CASE ELSE
            elif nxt_is_arm:
                pass  # next arm awaits its compare
            else:  # trailing CASE ELSE body
                fr.in_else = True
                fr.body_idx = len(o.stmts)
                # A CASE ELSE has no guard to recognise it by, so nothing else
                # in the log would mark where its body starts. It runs to the
                # END SELECT, which is known by now.
                fr.body_seq = state.region(
                    "case_else", start=i.ops[c.k][0], end=fr.end_select
                ).seq
            return True
        in_body = bool(c.cases) and c.cases[-1].body_jmp is not None
        # (3) Numeric entry: fstp64 [temp] to a scratch slot, arm header following.
        # An event-trapping poll hook lands at this join too, exactly as it does
        # at the string entry below -- the selector evaluation and the first arm
        # test are separate statements, so a trapping program stamps between
        # them. Without skipping it the SELECT is never recognised and the arms
        # decode as an IF chain, which recompiles to integer compares instead of
        # the selector's FP scratch cell (t1_selreftrap; wild resume.exe, 12
        # sites, and the whole of what was left of its round trip).
        head = _skip_hooks(state, c.k + 1)
        if (
            not in_body
            and kind == "fstp64"
            and op[2] < VAR_BASE
            and _is_arm_header_at(state, head)
            and _arm_temp_at(state, head) == op[2]
        ):
            state.branch(
                "case", template="select_header", target=None, address=c.cur
            )
            c.cases.append(SelectFrame(
                selector=e.stack.pop(),
                temp=op[2],
                is_string=False,
                start=c.cur,
            ))
            state.advance()
            c.cur = None
            return True
        # (3a) String entry: movsi [temp]; strassign to a scratch, string arm following.
        # The selector string was pushed to sstack by the preceding `movsi sel; rt`.
        # An event-trapping poll hook can land right at this exact join point
        # (wild rsltest.exe, under an active ON TIMER trap); tolerate it in the
        # lookahead sanity check -- the main dispatch loop consumes it normally
        # on its own turn regardless, so `c.k` below still only needs to
        # skip `movsi [temp]; strassign` itself.
        _hdr = c.k + 3 if _kind_at(state, c.k + 2) == "trap_hook" else c.k + 2
        if (
            not in_body
            and kind == "movsi"
            and op[2] < VAR_BASE
            and _kind_at(state, c.k + 1) == "strassign"
            and (
                _is_str_arm_header_at(state, _hdr, op[2])
                or _is_str_arm_header_chr_at(state, _hdr, op[2])
            )
        ):
            state.branch(
                "case", template="select_header", target=None, address=c.cur
            )
            c.cases.append(SelectFrame(
                selector=e.sstack.pop(),
                temp=op[2],
                is_string=True,
                start=c.cur,
            ))
            state.advance(2)  # consume movsi [temp]; strassign
            c.cur = None
            return True
        # (3b) String arm: movsi val; rt; movsi temp; rt; strcmp; je body; jmp next; body.
        if (
            c.cases
            and c.cases[-1].is_string
            and c.cases[-1].body_jmp is None
            and _is_str_arm_header_at(state, c.k, c.cases[-1].temp)
        ):
            return _str_guard_arm(state, c.k, state._pool_str(op[2]))
        # (3b-chr) String arm, computed CHR$(n) guard: movax n; strfn CHR$; movsi
        # temp; rt; strcmp; je body; jmp next; body -- same tail/positions as
        # (3b), just a computed value instead of a pooled literal/variable.
        if (
            c.cases
            and c.cases[-1].is_string
            and c.cases[-1].body_jmp is None
            and _is_str_arm_header_chr_at(state, c.k, c.cases[-1].temp)
        ):
            return _str_guard_arm(state, c.k, ir.Call("CHR$", (ir.Lit(op[2]),)))
        # (3.5) IS-relational arm: materialized-boolean compare idiom.
        if (
            c.cases
            and c.cases[-1].body_jmp is None
            and _is_is_mat_at(state, c.k)
        ):
            bound = e.stack.pop()
            relop = _IS_RELOP[i.ops[c.k + 3][2]]
            next_test = i.ops[c.k + 10][2]
            c.cases[-1].cur_guards.append(ir.CaseIs(relop, bound))
            _begin_body(state, c.k + 11, next_test)
            return True
        # (4) Arm compare: fcomp64 [temp] for an open frame; dispatch on jcc polarity.
        if c.cases and kind == "fcomp64" and op[2] == c.cases[-1].temp:
            val = e.stack.pop()
            cc, jcc_target = i.ops[c.k + 2][2], i.ops[c.k + 2][3]
            jmp_target = i.ops[c.k + 3][2]
            fr = c.cases[-1]
            if cc == 0x75:  # JNE: value-list non-final guard
                fr.cur_guards.append(ir.CaseValue(val))
                state.advance(4)
                c.cur = None
            elif cc == 0x76:  # JBE: range low bound
                fr.pending_range_lo = val
                state.advance(4)
                c.cur = None
            elif cc in (0x72, 0x73, 0x77):  # range high bound -> emit Range
                lo = fr.pending_range_lo
                fr.pending_range_lo = None
                fr.cur_guards.append(ir.CaseRange(lo, val))
                next_test = i.ops[_op_index_at(state, jcc_target)][2]
                _begin_body(state, _op_index_at(state, jmp_target), next_test)
            elif cc == 0x74:  # JE: literal final/only guard -> begin body
                fr.cur_guards.append(ir.CaseValue(val))
                _begin_body(state, c.k + 4, jmp_target)
            else:
                raise ValueError(f"SELECT CASE arm: unexpected jcc {cc:02x} at {addr:#x}")
            return True
        return False
