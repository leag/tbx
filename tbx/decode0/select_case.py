"""SELECT CASE recognizer: a state machine over the open `cases` frames.

`step(state)` is called once at the top of the decode loop; it returns True
when it consumed the current op(s) and the loop should `continue`, False to
let the op fall through to normal dispatch. All helpers thread the shared
:class:`~tbx.decode0.core.DecodeState` explicitly.
"""

from __future__ import annotations

from tbx import ir
from tbx.decode0.const import _IS_RELOP, VAR_BASE


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
            case_else = tuple(state.stmts[fr["body_idx"] :])
            del state.stmts[fr["body_idx"] :], state.addrs[fr["body_idx"] :]
        state.stmts.append(ir.SelectCase(fr["selector"], tuple(fr["arms"]), case_else))
        state.addrs.append(fr["start"])
        state.cur = None
        return False  # process the op at END SELECT normally
    # (2) Arm body close: the current op is this arm's trailing `jmp END_SELECT`.
    if state.cases and state.cases[-1]["body_jmp"] == addr:
        state.flush_pending()
        fr = state.cases[-1]
        body = tuple(state.stmts[fr["body_idx"] :])
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
    if (
        not in_body
        and kind == "movsi"
        and op[2] < VAR_BASE
        and _kind_at(state, state.k + 1) == "strassign"
        and _is_str_arm_header_at(state, state.k + 2, op[2])
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
        guard = state._pool_str(op[2])
        next_test = state.ops[state.k + 6][2]
        state.cases[-1]["cur_guards"].append(ir.CaseValue(guard))
        _begin_body(state, state.k + 7, next_test)
        return True
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
