"""Pure recognition tests for the operation-template matchers.

Each family gets two kinds of test: what the template accepts, spelled as a
small operation tuple, and the near misses it must reject. The rejection tests
are the ones that matter for the calibration rule -- a matcher that quietly
widened its template would decode a construct nobody compiled and verified.

These run on hand-built tuples, never a real EXE, so they say what the decoder
accepts without depending on any fixture.
"""

import pytest

from tbx import ir
from tbx.decode0.cursor import OpCursor
from tbx.decode0.matchers import (
    array_param_suffix,
    match_array_param_type,
    match_bool_bare_term1,
    match_bool_outer_and_group,
    match_bool_term1,
    match_string_logical_value_group,
    match_delay,
    match_fn_result_readback,
    match_for_header,
    match_loose_for_header,
    match_proc_body,
    match_return_to,
    match_using_chain_continues,
    match_using_emit,
)


# --------------------------------------------------------------------------
# compound booleans


def _and_term1_ops():
    """`A = B AND C`: term1 materializes, its jmp lands on term2's and ax,bx."""
    return [
        (0x100, "movax", 0xFFFF),
        (0x103, "jcc", 0x74, 0x106),
        (0x105, "incax"),
        (0x106, "orax"),
        (0x108, "jcc", 0x75, 0x10D),
        (0x10A, "jmp", 0x118),  # short circuit -> 0x116 + 2 (AND)
        (0x110, "movax", 0xFFFF),
        (0x113, "jcc", 0x74, 0x116),
        (0x115, "incax"),
        (0x116, "andaxbx"),
    ]


def test_bool_term1_names_template_operator_and_range():
    match = match_bool_term1(_and_term1_ops(), 0)

    assert match is not None
    assert match.template == "bool_term1"
    assert match.operator == "AND"
    assert match.polarity == 0x75
    assert match.short_circuit == 0x118
    assert (match.start, match.stop, match.consumed) == (0, 6, 6)
    assert match.deferred is False


def test_bool_term1_accepts_a_cursor_without_moving_it():
    cursor = OpCursor(_and_term1_ops())

    assert match_bool_term1(cursor) == match_bool_term1(_and_term1_ops(), 0)
    assert cursor.index == 0
    assert cursor.history == []


def test_bool_term1_rejects_a_cursor_with_a_separate_index():
    with pytest.raises(TypeError, match="separate index"):
        match_bool_term1(OpCursor(_and_term1_ops()), 0)


def test_bool_term1_requires_an_index_without_a_cursor():
    with pytest.raises(TypeError, match="index is required"):
        match_bool_term1(_and_term1_ops())


def test_bool_term1_defers_when_an_inner_group_materializes_first():
    # `A OR B AND C`: A's short circuit lands past B's own materialization, on
    # the (B AND C) group's convergence point.
    ops = [
        (0x100, "movax", 0xFFFF),
        (0x103, "jcc", 0x74, 0x106),
        (0x105, "incax"),
        (0x106, "orax"),
        (0x108, "jcc", 0x74, 0x10D),  # OR polarity
        (0x10A, "jmp", 0x130),
        (0x110, "movax", 0xFFFF),  # the inner group's own term
        (0x113, "jcc", 0x74, 0x116),
        (0x115, "incax"),
        (0x116, "andaxbx"),
        (0x12A, "movax", 0xFFFF),
        (0x12D, "jcc", 0x74, 0x130),
        (0x12F, "incax"),
        (0x130, "orax"),
    ]

    match = match_bool_term1(ops, 0)

    assert match is not None
    assert match.operator == "OR"
    assert match.deferred is True


@pytest.mark.parametrize(
    "mutate, why",
    [
        (lambda o: o.__setitem__(2, (0x105, "decax")), "header shape differs"),
        (
            lambda o: o.__setitem__(1, (0x103, "jcc", 0x74, 0x999)),
            "materialize branch misses the self-test",
        ),
        (
            lambda o: o.__setitem__(4, (0x108, "jcc", 0x73, 0x10D)),
            "gate polarity is neither AND (75) nor OR (74)",
        ),
        (
            lambda o: o.__setitem__(5, (0x10A, "jmp", 0x999)),
            "short circuit lands on no partner term",
        ),
        (
            lambda o: o.__setitem__(9, (0x116, "oraxdx")),
            "partner is not a calibrated combinator",
        ),
    ],
)
def test_bool_term1_rejects_near_misses(mutate, why):
    ops = _and_term1_ops()
    mutate(ops)
    before = list(ops)

    assert match_bool_term1(ops, 0) is None, why
    assert ops == before, "a matcher must not mutate the operation window"


def test_bool_bare_term1_matches_an_uncompared_and_term():
    ops = [
        (0x100, "orax"),
        (0x102, "jcc", 0x75, 0x107),
        (0x104, "jmp", 0x118),  # 0x116 + 2
        (0x110, "movax", 0xFFFF),
        (0x113, "jcc", 0x74, 0x116),
        (0x115, "incax"),
        (0x116, "andaxbx"),
    ]

    match = match_bool_bare_term1(ops, 0)

    assert match is not None
    assert match.template == "bool_bare_term1"
    assert match.operator == "AND"
    assert (match.start, match.stop) == (0, 3)


def test_bool_bare_term1_matches_an_uncompared_or_term():
    # OR's short circuit lands directly on the trailing OR combinator.
    # Calibrated by t1_bareor; wild cal.exe/cal87.exe.
    ops = [
        (0x100, "orax"),
        (0x102, "jcc", 0x74, 0x107),  # OR polarity
        (0x104, "jmp", 0x116),
        (0x110, "movax", 0xFFFF),
        (0x113, "jcc", 0x74, 0x116),
        (0x115, "incax"),
        (0x116, "orax"),
    ]

    match = match_bool_bare_term1(ops, 0)

    assert match is not None
    assert match.template == "bool_bare_term1"
    assert match.operator == "OR"
    assert match.short_circuit == 0x116


def test_bool_bare_term1_takes_only_the_first_materialization():
    # A later materialization belongs to a different term; matching against it
    # would fold two unrelated terms together.
    ops = [
        (0x100, "orax"),
        (0x102, "jcc", 0x75, 0x107),
        (0x104, "jmp", 0x148),
        (0x110, "movax", 0xFFFF),
        (0x113, "jcc", 0x74, 0x116),
        (0x115, "incax"),
        (0x116, "oraxdx"),  # not a combinator: decide here, do not scan on
        (0x140, "movax", 0xFFFF),
        (0x143, "jcc", 0x74, 0x146),
        (0x145, "incax"),
        (0x146, "andaxbx"),
    ]

    assert match_bool_bare_term1(ops, 0) is None


def test_return_to_matches_the_gosub_stack_unwind_and_jump():
    ops = [(0x100, "add_sp", 2), (0x103, "jmp", 0x80)]

    match = match_return_to(ops, 0)

    assert match is not None
    assert match.template == "return_to_gosub"
    assert match.target == 0x80
    assert match.consumed == 2


def test_return_to_rejects_other_stack_cleanup():
    ops = [(0x100, "add_sp", 4), (0x103, "jmp", 0x80)]

    assert match_return_to(ops, 0) is None


def test_bool_outer_and_group_matches_a_spilled_right_group():
    ops = [
        (0x100, "movax", 0xFFFF),
        (0x103, "jcc", 0x74, 0x106),
        (0x105, "incax"),
        (0x106, "orax"),
        (0x108, "jcc", 0x75, 0x10D),
        (0x10A, "jmp", 0x148),  # 0x146 + 2
        (0x120, "strcmp"),
        (0x130, "movrr", "cx", "bx"),
        (0x140, "movrr", "bx", "cx"),
        (0x146, "andaxbx"),
    ]

    match = match_bool_outer_and_group(ops, 0)

    assert match is not None
    assert match.template == "bool_outer_and_group"
    assert match.operator == "AND"
    assert (match.start, match.stop) == (0, 6)


def test_bool_outer_and_group_rejects_a_missing_convergence_and():
    ops = [
        (0x100, "movax", 0xFFFF),
        (0x103, "jcc", 0x74, 0x106),
        (0x105, "incax"),
        (0x106, "orax"),
        (0x108, "jcc", 0x75, 0x10D),
        (0x10A, "jmp", 0x148),
        (0x146, "oraxdx"),
    ]

    assert match_bool_outer_and_group(ops, 0) is None


def test_string_logical_value_group_matches_its_two_materializations():
    ops = [
        (0x0FE, "strcmp"),
        (0x100, "movax", 0xFFFF),
        (0x103, "jcc", 0x74, 0x106),
        (0x105, "incax"),
        (0x106, "movsi", 0x200),
        (0x109, "strcmp"),
        (0x10B, "movbxax"),
        (0x10D, "movax", 0xFFFF),
        (0x110, "jcc", 0x74, 0x113),
        (0x112, "incax"),
        (0x113, "oraxbx"),
        (0x115, "jcc", 0x74, 0x11A),
        (0x117, "jmp", 0x140),
    ]

    match = match_string_logical_value_group(ops, 1)

    assert match is not None
    assert match.operator == "OR"
    assert match.consumed == 12


def test_string_logical_value_group_accepts_a_numeric_right_relation():
    ops = [
        (0x0FE, "strcmp"),
        (0x100, "movax", 0xFFFF),
        (0x103, "jcc", 0x74, 0x106),
        (0x105, "incax"),
        (0x106, "fldz"),
        (0x109, "fcomp", 0x200),
        (0x10D, "fstsw"),
        (0x10F, "movbxax"),
        (0x111, "movax", 0xFFFF),
        (0x114, "jcc", 0x74, 0x117),
        (0x116, "incax"),
        (0x117, "andaxbx"),
        (0x119, "jcc", 0x75, 0x11E),
        (0x11B, "jmp", 0x140),
    ]

    match = match_string_logical_value_group(ops, 1)

    assert match is not None
    assert match.operator == "AND"


# --------------------------------------------------------------------------
# array parameter frames


def test_array_param_type_reads_the_suffix_off_a_later_access():
    ops = [
        (0x100, "arg_push_arr"),
        (0x104, "moves_bp", 0x0E),
        (0x108, "far_fild_si32"),
    ]

    match = match_array_param_type(ops, 0, block=0x0E)

    assert match is not None
    assert match.template == "array_param_type"
    assert match.block == 0x0E
    assert match.suffix == "&"
    assert match.terminal == "far_fild_si32"
    assert (match.start, match.stop) == (1, 3)
    assert array_param_suffix(ops, 0, 0x0E) == "&"


def test_array_param_type_stops_at_the_procedure_boundary():
    # A matching access in the NEXT procedure is an unrelated frame slot.
    ops = [
        (0x100, "arg_push_arr"),
        (0x104, "proc_ret"),
        (0x108, "moves_bp", 0x0E),
        (0x10C, "far_spush"),
    ]

    assert match_array_param_type(ops, 0, block=0x0E) is None
    # No evidence means the caller's own default stands, not a guessed type.
    assert array_param_suffix(ops, 0, 0x0E) == ""


def test_array_param_type_ignores_a_different_frame_offset():
    ops = [
        (0x100, "arg_push_arr"),
        (0x104, "moves_bp", 0x10),
        (0x108, "far_spush"),
    ]

    assert match_array_param_type(ops, 0, block=0x0E) is None


def test_array_param_type_skips_an_access_whose_terminal_carries_no_type():
    ops = [
        (0x100, "arg_push_arr"),
        (0x104, "moves_bp", 0x0E),
        (0x108, "arg_push_arr"),  # bare pointer push: witnesses nothing
        (0x10C, "moves_bp", 0x0E),
        (0x110, "far_strassign"),
    ]

    match = match_array_param_type(ops, 0, block=0x0E)

    assert match is not None
    assert match.suffix == "$"
    assert match.start == 3


def test_array_param_type_requires_a_block_offset():
    with pytest.raises(TypeError, match="block offset is required"):
        match_array_param_type([(0x100, "moves_bp", 0x0E)], 0)


# --------------------------------------------------------------------------
# timing


def test_match_delay_returns_consumption_and_hook_facts():
    ops = [
        (0x10, "delay_init"),
        (0x11, "trap_hook", 100),
        (0x12, "delay_poll"),
        (0x13, "jcc", 0x75, 0x11),
        (0x14, "end"),
    ]

    match = match_delay(ops, 0)

    assert match is not None
    assert match.template == "delay"
    assert match.hooks == (ops[1],)
    assert match.loop_back == 0x11
    assert (match.start, match.stop, match.consumed) == (0, 4, 4)
    assert match_delay(OpCursor(ops)) == match


def test_match_delay_rejects_near_misses_without_mutation():
    ops = [(0x10, "delay_init"), (0x11, "delay_poll"), (0x12, "jmp", 0x99)]
    before = list(ops)

    assert match_delay(ops, 0) is None
    assert ops == before
    assert match_delay(ops, 1) is None


# --------------------------------------------------------------------------
# procedure frames


def test_proc_body_names_the_string_epilogue_as_the_exit():
    ops = [
        (0x100, "proc_enter"),
        (0x104, "movax", 1),
        (0x108, "arg_ref", 0x0E),
        (0x10C, "str_temp_free"),
        (0x110, "arg_ref", 0x12),
        (0x114, "str_temp_free"),
        (0x118, "proc_ret"),
    ]

    match = match_proc_body(ops, 0)

    assert match is not None
    assert match.template == "proc_body"
    assert match.ret_address == 0x118
    # EXIT SUB jumps to the first freeing pair, not to the proc_ret.
    assert match.exit_address == 0x108
    assert match.freed_strings == 2
    assert (match.start, match.stop) == (0, 7)


def test_proc_body_without_string_locals_exits_at_the_return():
    ops = [(0x100, "proc_enter"), (0x104, "movax", 1), (0x108, "proc_ret")]

    match = match_proc_body(ops, 0)

    assert match is not None
    assert match.ret_address == match.exit_address == 0x108
    assert match.freed_strings == 0


def test_proc_body_does_not_walk_back_past_its_own_entry():
    # A freeing pair belonging to an EARLIER procedure must not be absorbed.
    ops = [
        (0x0F0, "arg_ref", 0x0E),
        (0x0F4, "str_temp_free"),
        (0x100, "proc_enter"),
        (0x108, "proc_ret"),
    ]

    match = match_proc_body(ops, 2)

    assert match is not None
    assert match.exit_address == 0x108
    assert match.freed_strings == 0


def test_proc_body_reports_a_missing_return_as_no_match():
    assert match_proc_body([(0x100, "proc_enter"), (0x104, "movax", 1)], 0) is None


def test_fn_result_readback_skips_register_shuttle_boilerplate():
    ops = [
        (0x100, "fn_call", 0x200),
        (0x104, "movbxax"),
        (0x106, "movax_bp", 0),
    ]

    match = match_fn_result_readback(ops, 2)

    assert match is not None
    assert match.template == "fn_result_readback"
    assert (match.start, match.stop) == (0, 3)


def test_fn_result_readback_requires_the_shared_frame_slot():
    # bp+2 is the enclosing SUB's own local, not the staged FN result.
    ops = [(0x100, "fn_call", 0x200), (0x104, "movax_bp", 2)]

    assert match_fn_result_readback(ops, 1) is None


def test_fn_result_readback_rejects_a_computing_operation_in_between():
    # Only register shuttles may intervene: anything that computes a value
    # means bp+0 is not the call's result any more.
    ops = [
        (0x100, "fn_call", 0x200),
        (0x104, "addax_m", 0x10),
        (0x108, "movax_bp", 0),
    ]

    assert match_fn_result_readback(ops, 2) is None


# --------------------------------------------------------------------------
# runtime-vector dispatch


@pytest.mark.parametrize(
    "emit_vec, item_vec, numeric, leg",
    [
        (0xCB, 0xBE, True, "console"),
        (0xCB, 0xC0, True, "file"),
        (0xCB, 0xBF, True, "printer"),
        (0xCC, 0xBE, False, "console"),
    ],
)
def test_using_emit_names_the_item_kind_and_leg(emit_vec, item_vec, numeric, leg):
    ops = [(0x100, "rt", emit_vec), (0x104, "rt", item_vec)]

    match = match_using_emit(ops, 0)

    assert match is not None
    assert match.template == "using_emit"
    assert match.numeric is numeric
    assert match.leg == leg
    assert (match.start, match.stop) == (0, 2)


def test_using_emit_rejects_an_emit_without_its_item_vector():
    # A stray emit stays fail-loud in the applier rather than being folded
    # into whatever chain happens to be open.
    assert match_using_emit([(0x100, "rt", 0xCB), (0x104, "rt", 0xCA)], 0) is None
    assert match_using_emit([(0x100, "rt", 0xCB)], 0) is None
    assert match_using_emit([(0x100, "rt", 0xBE), (0x104, "rt", 0xBE)], 0) is None


def test_using_chain_continues_finds_the_emit_that_claims_the_item():
    ops = [
        (0x100, "tabspc", 0x10),
        (0x104, "movax", 5),
        (0x108, "rt", 0xCB),
    ]

    match = match_using_chain_continues(ops, 0)

    assert match is not None
    assert (match.start, match.stop) == (2, 3)


def test_using_chain_stops_at_a_terminator_before_a_later_chain():
    # The CA opens a NEW chain; the emit after it belongs to that one.
    ops = [
        (0x100, "tabspc", 0x10),
        (0x104, "rt", 0xCA),
        (0x108, "rt", 0xCB),
    ]

    assert match_using_chain_continues(ops, 0) is None


def test_using_chain_lookahead_is_bounded():
    ops = [(0x100, "tabspc", 0x10)]
    ops += [(0x104 + 4 * n, "movax", n) for n in range(20)]
    ops.append((0x200, "rt", 0xCB))

    assert match_using_chain_continues(ops, 0) is None


# --------------------------------------------------------------------------
# FOR headers (materialized tests)


def _vdisp(var):
    return int(var.name[1:], 16)


def _staged(limit, step, init):
    return [
        ir.Assign(ir.Var(f"V{limit:04X}"), ir.Lit(10)),
        ir.Assign(ir.Var(f"V{step:04X}"), ir.Lit(1)),
        ir.Assign(ir.Var(f"V{init:04X}"), ir.Lit(0)),
    ]


def test_for_header_matches_the_canonical_slot_layout():
    match = match_for_header(_staged(0x3D0, 0x3CC, 0x3D4), _vdisp)

    assert match is not None
    assert match.template == "for_header"
    assert (match.limit, match.step, match.var) == (0x3D0, 0x3CC, 0x3D4)
    # Recognized entirely from committed statements: no operations consumed.
    assert (match.start, match.stop, match.consumed) == (0, 0, 0)


def test_for_header_rejects_non_adjacent_slots():
    assert match_for_header(_staged(0x3D0, 0x3C0, 0x3D4), _vdisp) is None


def test_for_header_rejects_trailing_string_assignments():
    # Consecutive string slots are ALSO 4 bytes apart, so three trailing
    # string assigns before a GOTO could otherwise false-positive
    # (t1_strgoto, wild inv87.exe).
    stmts = [
        ir.Assign(ir.Var("V03D0$"), ir.StrLit("a")),
        ir.Assign(ir.Var("V03CC$"), ir.StrLit("b")),
        ir.Assign(ir.Var("V03D4$"), ir.StrLit("c")),
    ]

    assert match_for_header(stmts, _vdisp) is None


def test_for_header_needs_three_assignments():
    assert match_for_header(_staged(0x3D0, 0x3CC, 0x3D4)[1:], _vdisp) is None


def test_loose_for_header_rejects_a_bare_testw():
    # An arbitrary testw must not become a FOR just because three assignments
    # happen to precede it.
    ops = [(0x100, "testw", 0x3CE, 0x8000), (0x108, "jcc", 0x74, 0x10D)]

    assert (
        match_loose_for_header(ops, 0, _staged(0x3D0, 0x3CC, 0x3D4), _vdisp) is None
    )
