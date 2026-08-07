"""The skip-jmp that brackets a definition interleaved into main code.

Three of the four bracket rules in `core` recognize the jmp by what precedes
it -- the entry jmp, a jmp landed on by the previous bracket, a jmp sitting
where a definition just closed. A definition interleaved BEHIND ordinary main
code fits none of them: the op before its bracket is a user `RETURN` (wild
cleanup.exe, reformat.exe, crossref.exe, all three stopping at `LOCAL zero-fill
outside a fresh SUB/DEF FN body`), or an event-trap `return_to` (prtguide.exe,
where the bracket was lifted as a spurious user GOTO instead).

`match_definition_bracket` recognizes it by what it does: lands exactly past
the closer of the body it opens. Fixture t1_gosubthendef.
"""

from tbx.decode0.matchers import match_definition_bracket as match


def _fn(target, closer_at=0x20, after=0x22, trap=False):
    """jmp -> block DEF FN body -> fn_ret at `closer_at` -> op at `after`."""
    ops = [(0x10, "jmp", target), (0x13, "mov_bp_imm", 0, 0)]
    ops.append((closer_at, "fn_ret"))
    if trap:
        ops.append((closer_at + 1, "trap_hook"))
    ops.append((after, "movsi", 4))
    return ops


def test_matches_block_def_fn_bracket():
    assert match(_fn(0x22), 0).target == 0x22


def test_matches_across_the_trap_stamps_event_trapping_leaves():
    # The closer's trailing `trap_hook` is where a trapping build puts the
    # stamp; the bracket still lands past it (prtguide.exe).
    assert match(_fn(0x22, trap=True), 0).target == 0x22


def test_matches_a_proc_enter_body():
    ops = [
        (0x10, "jmp", 0x22),
        (0x13, "proc_enter", 4),
        (0x20, "proc_ret", 0),
        (0x22, "movsi", 4),
    ]
    assert match(ops, 0).target == 0x22


def test_rejects_a_jmp_landing_short_of_the_closer():
    # A user GOTO into the middle of the region is not a bracket.
    assert match(_fn(0x1C, after=0x22), 0) is None


def test_rejects_a_jmp_landing_past_the_closer():
    assert match(_fn(0x30, after=0x22), 0) is None


def test_rejects_a_backward_jmp():
    ops = _fn(0x22)
    ops[0] = (0x10, "jmp", 0x08)
    assert match(ops, 0) is None


def test_rejects_a_jmp_not_followed_by_a_definition():
    ops = [(0x10, "jmp", 0x22), (0x13, "movsi", 4), (0x20, "fn_ret"), (0x22, "movsi", 4)]
    assert match(ops, 0) is None


def test_rejects_a_nonzero_bp_init():
    # Only `mov [bp+0],0` opens a block DEF FN; `[bp+2],0` alone is the
    # single-line STRING form and carries no closer of its own here.
    ops = _fn(0x22)
    ops[1] = (0x13, "mov_bp_imm", 2, 0)
    assert match(ops, 0) is None


def test_rejects_a_non_jmp():
    assert match([(0x10, "movsi", 4), (0x13, "proc_enter", 4)], 0) is None
