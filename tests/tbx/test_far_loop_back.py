"""A head-test DO loop's retry edge is not always a *short* jmp.

`_has_jmps_back` is what separates a head-test `DO WHILE/UNTIL` from an
inline-IF body skip: both compile the same materialization template, and the
loop is the one whose body ends by branching back to the test. It looked for
that retry edge as op kind `jmps` -- `EB`, jmp short rel8.

Which encoding the compiler picks is decided by reach, not by construct: once
the body is longer than rel8 spans, the same retry edge is emitted as `E9`,
jmp near rel16, and scans as op kind `jmp`. So the loop stopped being
recognised for no reason the source can see, and fell through to
`unhandled materialized test` -- wild varamort.exe (1.0) and football.exe
(1.1), both `DO UNTIL <string compare>` around a few hundred bytes of body.

Only a *string* condition reaches this path at all: a numeric relop branches on
its own flags, so `DO UNTIL A >= 3` never materializes however long its body is
(that spelling was tried first here and decoded fine at any length). `strcmp`
leaves no such flag to branch on, which is why both witnesses compare strings.

**The near form is admitted only at cc 74, and that asymmetry is the point.**
At cc 75 the inline/block-IF branch is a live competing reading, and the two
are not distinguishable: measured on our own oracle, `DO WHILE c` ... `LOOP`
and `IF c THEN` ... `GOTO <that line>` ... `END IF` over one 20-statement body
compile to byte-identical EXEs -- 0 bytes differ. Either spelling round-trips,
so nothing about the bytes prefers the loop, and the corpus is already
calibrated on the IF reading (wild state.exe, state87.exe, inv87.exe and
invoice.exe each carry two such sites; widening cc 75 too moved 124 statements
in state.exe and changed nothing that was wrong). At cc 74 there is no IF
reading -- that branch takes 75 only -- so the loop is the only reading, and
the near form has to be admitted for it to be reached.

The adjacency the docstring already claimed -- the retry edge sits immediately
*before* the exit address -- is now what the search anchors on, rather than
scanning forward for the first branch that happens to target the test. A near
jmp to a loop's test address is also just what a `GOTO` to that line compiles
to from anywhere in the program, so with the near form admitted, targeting the
test is no longer evidence enough on its own.
"""

from pathlib import Path

import pytest

from tbx import decode0, emit0
from tbx.decode0 import _has_jmps_back

_ROOT = Path(__file__).resolve().parents[2]
_CORPUS = _ROOT / "tests" / "fixtures" / "corpus"


def test_a_short_retry_edge_is_still_the_loop_back():
    """The `EB` form every calibrated fixture carries must keep matching."""
    ops = [(0x100, "jmps", 0x50), (0x102, "end")]

    assert _has_jmps_back(ops, exit_addr=0x102, test_addr=0x50)


def test_a_near_retry_edge_counts_only_when_asked_for():
    """`E9` is the same edge, but the default stays short-only.

    Every other caller decides something this evidence is too weak for, so
    admitting the near form is opt-in rather than the helper's new baseline.
    """
    ops = [(0x100, "jmp", 0x50), (0x103, "end")]

    assert not _has_jmps_back(ops, exit_addr=0x103, test_addr=0x50)
    assert _has_jmps_back(ops, exit_addr=0x103, test_addr=0x50, near=True)


def test_a_branch_to_the_test_from_elsewhere_is_not_the_loop_back():
    """What makes the edge the retry edge is that the exit follows it.

    A near jmp targeting the test address is also how a `GOTO` to that line
    compiles, so once the near form is admitted the target alone cannot decide
    it. Here one sits mid-program with real code after it, and no adjacent
    edge exists at all.
    """
    ops = [(0x100, "jmp", 0x50), (0x103, "movax", 1), (0x106, "end")]

    assert not _has_jmps_back(ops, exit_addr=0x106, test_addr=0x50, near=True)


def test_the_retry_edge_must_reach_back_to_this_loops_test():
    """Adjacency alone is not enough either -- it has to target the test."""
    ops = [(0x100, "jmp", 0x900), (0x103, "end")]

    assert not _has_jmps_back(ops, exit_addr=0x103, test_addr=0x50, near=True)


def test_the_real_edge_is_found_past_an_unrelated_goto_to_the_test():
    """Why the search anchors on the exit rather than on the target.

    The first branch targeting the test is a plain `GOTO` mid-body; the retry
    edge is the one further down. Scanning for the target used to answer with
    the GOTO and return False.
    """
    ops = [
        (0x100, "jmp", 0x50),  # a source GOTO back to that line
        (0x103, "movax", 1),
        (0x106, "jmp", 0x50),  # the actual retry edge
        (0x109, "end"),
    ]

    assert _has_jmps_back(ops, exit_addr=0x109, test_addr=0x50, near=True)


@pytest.mark.parametrize("stem", ("t1_dofarback", "v10_t1_dofarback"))
def test_a_far_bodied_head_test_loop_decodes_as_a_loop(stem):
    """The whole construct, in both dialects, as `DO UNTIL ... LOOP`.

    Used to raise `unhandled materialized test`: the template matched, the
    retry edge was there, and it was rejected only for being encoded near.
    """
    prog = decode0.decode_user_code((_CORPUS / f"{stem}.exe").read_bytes())
    lines = emit0.emit(prog).splitlines()

    assert '20 DO UNTIL A$ = "Y"' in lines, lines
    # The retry edge, which used to come out as `GOTO 20` with the frame never
    # closed -- the half of the gap that outlived widening `_has_jmps_back`.
    assert "240 LOOP" in lines, lines


def test_the_loop_body_really_did_outgrow_a_short_jmp():
    """Guards the fixture itself: shorten the body and it stops witnessing.

    The gap only exists past rel8 reach, so a fixture that drifted under it
    would keep passing while testing nothing.
    """
    golden = _ROOT / "tests" / "fixtures" / "ops" / "t1_dofarback.txt"

    backward_near = []
    for line in golden.read_text().splitlines():
        parts = line.split(":")
        if len(parts) == 3 and parts[1] == "jmp":
            at, target = int(parts[0], 16), int(parts[2])
            if 128 < at - target:  # backward, past rel8 reach
                backward_near.append((at, target))

    assert backward_near, "fixture no longer carries a near backward jmp"


def test_an_ambiguous_cc75_site_keeps_its_guard_reading():
    """The near form must NOT be admitted where an IF guard reading competes.

    state.exe's cursor loop at 0xd9db is the site this was traced on: cc 75,
    retry edge `jmp 0xd9db` at 0xe94c immediately before the exit at 0xe94f.
    Reading it as `DO WHILE AO$ <> CHR$(13)` is not *wrong* -- it recompiles to
    the same bytes as the guard -- but it is not more right either, and it
    is not what the corpus is calibrated on. `test_wild_subset` pins the
    statement counts for this program and its three siblings; this names the
    reason those counts are load-bearing, so a future widening has to argue
    with it rather than regenerate past it.
    """
    hits = _ROOT / "wild" / "hits" / "state.exe"
    if not hits.is_file():  # wild/hits is gitignored
        pytest.skip("state.exe not present")

    source = emit0.emit(decode0.decode_user_code(hits.read_bytes()))

    assert "DO WHILE AO$ <> CHR$(13)" not in source
    assert "IF AO$ = CHR$(13) THEN" in source
