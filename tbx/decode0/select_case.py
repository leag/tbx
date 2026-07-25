"""SELECT CASE recognizer: a state machine over the open `cases` frames.

`step(state)` is called once at the top of the decode loop; it returns True
when it consumed the current op(s) and the loop should `continue`, False to
let the op fall through to normal dispatch. All helpers thread the shared
:class:`~tbx.decode0.core.DecodeState` explicitly.
"""

from __future__ import annotations

from tbx import ir
from tbx.decode0.const import _IS_RELOP, VAR_BASE
from tbx.decode0.lift import _fold_if, _jump_targets


def _kind_at(state, i):
    return state.ops[i][1] if 0 <= i < len(state.ops) else None


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


def _is_arm_header_at(state, i):
    return _kind_at(state, i) in ("fld1", "fild", "fld") and (
        _kind_at(state, i + 1) == "fcomp64" or _is_is_mat_at(state, i + 1)
    )


def _arm_temp_at(state, i):
    if _kind_at(state, i + 1) == "fcomp64":
        return state.ops[i + 1][2]
    if _kind_at(state, i + 1) == "fcomp" and _kind_at(state, i + 8) == "fcomp64":
        return state.ops[i + 8][2]
    return None


def _is_str_arm_header_at(state, i, temp):
    return (
        _kind_at(state, i) == "movsi"
        and _kind_at(state, i + 1) == "rt"
        and state.ops[i + 1][2] == 0x9C
        and _kind_at(state, i + 2) == "movsi"
        and state.ops[i + 2][2] == temp
        and _kind_at(state, i + 3) == "rt"
        and state.ops[i + 3][2] == 0x9C
        and _kind_at(state, i + 4) == "strcmp"
    )


def _is_str_arm_header_chr_at(state, i, temp):
    # A CHR$(n) guard (wild rsltest.exe: `case chr$(72),chr$(75),"-",...`,
    # mixing computed and bare-literal guards in one arm list) computes the
    # value at the guard site instead of loading an existing descriptor --
    # movax n; strfn CHR$ where the bare form's leading movsi/rt pair sits.
    return (
        _kind_at(state, i) == "movax"
        and _kind_at(state, i + 1) == "strfn"
        and state.ops[i + 1][2] == "CHR$"
        and _kind_at(state, i + 2) == "movsi"
        and state.ops[i + 2][2] == temp
        and _kind_at(state, i + 3) == "rt"
        and state.ops[i + 3][2] == 0x9C
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
    jcc = state.ops[k + 5]
    state.cases[-1]["cur_guards"].append(ir.CaseValue(guard))
    if jcc[2] == 0x75:  # JNE: value-list non-final guard -- keep testing
        state.k = k + 7
        state.cur = None
        return True
    if jcc[2] == 0x74:  # JE: literal final/only guard -> begin body
        next_test = state.ops[k + 6][2]
        _begin_body(state, k + 7, next_test)
        return True
    raise ValueError(
        f"SELECT CASE string arm: unexpected jcc {jcc[2]:02x} at {state.ops[k][0]:#x}"
    )


def _op_index_at(state, a):
    for i, o in enumerate(state.ops):
        if o[0] == a:
            return i
    return None


def _begin_body(state, body_i, next_test):
    i = body_i
    while i < len(state.ops) and state.ops[i][0] < next_test:
        i += 1
    if i == body_i:
        raise ValueError("SELECT CASE arm: empty body")
    last_jmp_target = state.ops[i - 1][2] if state.ops[i - 1][1] == "jmp" else None
    fr = state.cases[-1]
    fr["next_test"] = next_test
    fr["body_idx"] = len(state.stmts)
    if last_jmp_target is not None:
        fr["body_jmp"] = state.ops[i - 1][0]
        if fr["end_select"] == 0:
            fr["end_select"] = last_jmp_target
    else:  # flow-through final arm (no trailing jmp)
        if fr["end_select"] == 0 or next_test != fr["end_select"]:
            raise ValueError("SELECT CASE arm: flow-through without known END SELECT")
        fr["body_jmp"] = next_test
    state.k = body_i
    state.cur = None


def _fold_arm(state, body_idx, merge):
    """Block-fold the arm (or CASE ELSE) body sitting at `state.stmts[body_idx:]`
    and return it as a tuple, addresses retained.

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
    # An inline IF closing this arm skips to the arm-close address, and
    # `select_case.step` runs BEFORE the dispatch loop's own close point -- so
    # drain those bodies here or the arm folds away with one still open
    # (TBW73.INC:716, via DecodeState.open_tail_if).
    state.close_ifs(merge)
    stmts, addrs = _fold_if(
        state.stmts[body_idx:],
        state.addrs[body_idx:],
        bound=merge,
        targets=_jump_targets(state.stmts),
        stmt_addr=state.stmt_addr,
        block_ifs=state.block_if_addrs,
    )
    state.stmts[body_idx:], state.addrs[body_idx:] = stmts, addrs
    body = tuple(state.stmts[body_idx:])
    _keep_addrs(state, body, body_idx)
    return body


def _keep_addrs(state, body, body_idx) -> None:
    """Carry an arm/CASE-ELSE body's statement addresses into `state.stmt_addr`
    before the snapshot deletes them from `state.addrs`.

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
    for st, ad in zip(body, state.addrs[body_idx:]):
        if ad is not None:
            state.stmt_addr[id(st)] = ad


def step(state):
    op = state.ops[state.k]
    addr, kind = op[0], op[1]
    # (1) END SELECT: every arm body has jumped here -> emit the statement.
    if (
        state.cases
        and state.cases[-1]["body_jmp"] is None
        and addr == state.cases[-1]["end_select"]
    ):
        state.flush_pending()
        fr = state.cases.pop()
        case_else = None
        if fr["in_else"]:
            case_else = _fold_arm(state, fr["body_idx"], addr)
            del state.stmts[fr["body_idx"] :], state.addrs[fr["body_idx"] :]
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
        state.stmts.append(ir.SelectCase(fr["selector"], tuple(fr["arms"]), case_else))
        state.addrs.append(fr["start"])
        state.cur = None
        return False  # process the op at END SELECT normally
    # (2) Arm body close: the current op is this arm's trailing `jmp END_SELECT`.
    if state.cases and state.cases[-1]["body_jmp"] == addr:
        state.flush_pending()
        fr = state.cases[-1]
        body = _fold_arm(state, fr["body_idx"], addr)
        del state.stmts[fr["body_idx"] :], state.addrs[fr["body_idx"] :]
        fr["arms"].append(ir.CaseArm(tuple(fr["cur_guards"]), body))
        fr["cur_guards"] = []
        fr["body_jmp"] = None
        if kind != "jmp":  # flow-through final arm closes AT END SELECT
            return True
        state.k += 1  # consume the trailing jmp
        state.cur = None
        nxt_is_arm = (
            _is_str_arm_header_at(state, state.k, fr["temp"])
            if fr["is_string"]
            else _is_arm_header_at(state, state.k)
        )
        if fr["next_test"] == fr["end_select"]:
            pass  # no CASE ELSE
        elif nxt_is_arm:
            pass  # next arm awaits its compare
        else:  # trailing CASE ELSE body
            fr["in_else"] = True
            fr["body_idx"] = len(state.stmts)
        return True
    in_body = bool(state.cases) and state.cases[-1]["body_jmp"] is not None
    # (3) Numeric entry: fstp64 [temp] to a scratch slot, arm header following.
    if (
        not in_body
        and kind == "fstp64"
        and op[2] < VAR_BASE
        and _is_arm_header_at(state, state.k + 1)
        and _arm_temp_at(state, state.k + 1) == op[2]
    ):
        state.cases.append(
            {
                "selector": state.stack.pop(),
                "temp": op[2],
                "is_string": False,
                "end_select": 0,
                "arms": [],
                "cur_guards": [],
                "pending_range_lo": None,
                "body_idx": 0,
                "body_jmp": None,
                "next_test": 0,
                "in_else": False,
                "start": state.cur,
            }
        )
        state.k += 1
        state.cur = None
        return True
    # (3a) String entry: movsi [temp]; strassign to a scratch, string arm following.
    # The selector string was pushed to sstack by the preceding `movsi sel; rt`.
    # An event-trapping poll hook can land right at this exact join point
    # (wild rsltest.exe, under an active ON TIMER trap); tolerate it in the
    # lookahead sanity check -- the main dispatch loop consumes it normally
    # on its own turn regardless, so `state.k` below still only needs to
    # skip `movsi [temp]; strassign` itself.
    _hdr = state.k + 3 if _kind_at(state, state.k + 2) == "trap_hook" else state.k + 2
    if (
        not in_body
        and kind == "movsi"
        and op[2] < VAR_BASE
        and _kind_at(state, state.k + 1) == "strassign"
        and (
            _is_str_arm_header_at(state, _hdr, op[2])
            or _is_str_arm_header_chr_at(state, _hdr, op[2])
        )
    ):
        state.cases.append(
            {
                "selector": state.sstack.pop(),
                "temp": op[2],
                "is_string": True,
                "end_select": 0,
                "arms": [],
                "cur_guards": [],
                "pending_range_lo": None,
                "body_idx": 0,
                "body_jmp": None,
                "next_test": 0,
                "in_else": False,
                "start": state.cur,
            }
        )
        state.k += 2  # consume movsi [temp]; strassign
        state.cur = None
        return True
    # (3b) String arm: movsi val; rt; movsi temp; rt; strcmp; je body; jmp next; body.
    if (
        state.cases
        and state.cases[-1]["is_string"]
        and state.cases[-1]["body_jmp"] is None
        and _is_str_arm_header_at(state, state.k, state.cases[-1]["temp"])
    ):
        return _str_guard_arm(state, state.k, state._pool_str(op[2]))
    # (3b-chr) String arm, computed CHR$(n) guard: movax n; strfn CHR$; movsi
    # temp; rt; strcmp; je body; jmp next; body -- same tail/positions as
    # (3b), just a computed value instead of a pooled literal/variable.
    if (
        state.cases
        and state.cases[-1]["is_string"]
        and state.cases[-1]["body_jmp"] is None
        and _is_str_arm_header_chr_at(state, state.k, state.cases[-1]["temp"])
    ):
        return _str_guard_arm(state, state.k, ir.Call("CHR$", (ir.Lit(op[2]),)))
    # (3.5) IS-relational arm: materialized-boolean compare idiom.
    if (
        state.cases
        and state.cases[-1]["body_jmp"] is None
        and _is_is_mat_at(state, state.k)
    ):
        bound = state.stack.pop()
        relop = _IS_RELOP[state.ops[state.k + 3][2]]
        next_test = state.ops[state.k + 10][2]
        state.cases[-1]["cur_guards"].append(ir.CaseIs(relop, bound))
        _begin_body(state, state.k + 11, next_test)
        return True
    # (4) Arm compare: fcomp64 [temp] for an open frame; dispatch on jcc polarity.
    if state.cases and kind == "fcomp64" and op[2] == state.cases[-1]["temp"]:
        val = state.stack.pop()
        cc, jcc_target = state.ops[state.k + 2][2], state.ops[state.k + 2][3]
        jmp_target = state.ops[state.k + 3][2]
        fr = state.cases[-1]
        if cc == 0x75:  # JNE: value-list non-final guard
            fr["cur_guards"].append(ir.CaseValue(val))
            state.k += 4
            state.cur = None
        elif cc == 0x76:  # JBE: range low bound
            fr["pending_range_lo"] = val
            state.k += 4
            state.cur = None
        elif cc == 0x72:  # JB: range high bound -> emit Range, begin body
            lo = fr["pending_range_lo"]
            fr["pending_range_lo"] = None
            fr["cur_guards"].append(ir.CaseRange(lo, val))
            next_test = state.ops[_op_index_at(state, jcc_target)][2]
            _begin_body(state, _op_index_at(state, jmp_target), next_test)
        elif cc == 0x74:  # JE: literal final/only guard -> begin body
            fr["cur_guards"].append(ir.CaseValue(val))
            _begin_body(state, state.k + 4, jmp_target)
        else:
            raise ValueError(f"SELECT CASE arm: unexpected jcc {cc:02x} at {addr:#x}")
        return True
    return False
