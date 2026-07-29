"""The statement list records every edit made to it.

Statements do not only arrive through `put`: pending chains flush directly,
handlers patch an already-committed statement in place, folding deletes and
inserts, and finalization reconstructs DIM/DATA from layout facts. Recording
at the call sites means remembering to, at twenty of them.

So the list itself records. `replay` rebuilding the exact final list is the
losslessness property -- if an edit were unrecorded, replay would diverge.
"""

import pytest

from tbx import ir
from tbx.decode0.statement_log import RecordedStatements, replay


def test_append_is_recorded():
    stmts = RecordedStatements()

    stmts.append(ir.End())

    assert list(stmts) == [ir.End()]
    assert replay(stmts.edits) == [ir.End()]


def test_in_place_replacement_is_recorded():
    # The LOCATE cursor argument arrives after the statement is committed.
    stmts = RecordedStatements()
    stmts.append(ir.Locate(ir.Lit(1), ir.Lit(2)))

    stmts[-1] = ir.Locate(ir.Lit(1), ir.Lit(2), ir.Lit(0))

    assert replay(stmts.edits) == list(stmts)
    assert stmts.edits[-1].kind == "replace"


def test_insertion_is_recorded():
    stmts = RecordedStatements([ir.End()])

    stmts.insert(0, ir.Do(None))

    assert replay(stmts.edits) == [ir.Do(None), ir.End()]


def test_deletion_is_recorded():
    stmts = RecordedStatements([ir.Do(None), ir.End()])

    del stmts[0]

    assert replay(stmts.edits) == [ir.End()]


def test_slice_assignment_is_recorded():
    # Folding rewrites whole regions: `stmts[body_idx:] = folded`.
    stmts = RecordedStatements([ir.End(), ir.Goto(1), ir.Goto(2)])

    stmts[1:] = [ir.Do(None)]

    assert replay(stmts.edits) == [ir.End(), ir.Do(None)]


def test_whole_list_replacement_is_recorded():
    # `stmts[:] = [...]` is how finalization filters the list.
    stmts = RecordedStatements([ir.End(), ir.Goto(1)])

    stmts[:] = [ir.Goto(1)]

    assert replay(stmts.edits) == [ir.Goto(1)]


def test_replay_reproduces_a_mixed_edit_sequence():
    stmts = RecordedStatements()
    stmts.append(ir.Goto(("addr", 0x10)))
    stmts.append(ir.End())
    stmts.insert(1, ir.Do(None))
    stmts[0] = ir.Goto(("addr", 0x20))
    del stmts[2]

    assert replay(stmts.edits) == list(stmts)


def test_pop_is_recorded():
    stmts = RecordedStatements([ir.Do(None), ir.End()])

    popped = stmts.pop()

    assert popped == ir.End()
    assert replay(stmts.edits) == [ir.Do(None)]


def test_an_unrecorded_edit_would_break_replay():
    """Guard on the guard: replay only proves losslessness if it can fail."""
    stmts = RecordedStatements([ir.End()])

    list.append(stmts, ir.Goto(1))  # bypasses the recorder on purpose

    assert replay(stmts.edits) != list(stmts)


@pytest.mark.parametrize("index", [0, 1, -1])
def test_replace_at_any_index_replays(index):
    stmts = RecordedStatements([ir.End(), ir.Goto(1)])

    stmts[index] = ir.Do(None)

    assert replay(stmts.edits) == list(stmts)


def test_a_real_decode_replays_its_statement_edits_exactly():
    """The losslessness property, on a real program rather than a fixture list.

    `_finalize` enforces this for every decode; this pins it as a test so the
    property is stated somewhere a reader will find it.
    """
    from pathlib import Path

    from tbx import decode0
    from tbx.decode0.statement_log import replay as replay_edits

    corpus = Path(__file__).resolve().parents[1] / "fixtures" / "corpus"
    prog = decode0.decode_user_code((corpus / "t1_ifblockselect.exe").read_bytes())

    assert prog.statement_edits
    # Replay reaches the pre-canonical statement list; the program has since
    # been renamed and had its targets resolved, so compare the shapes.
    rebuilt = replay_edits(prog.statement_edits)
    assert len(rebuilt) == len(prog)
    assert [type(s).__name__ for s in rebuilt] == [type(s).__name__ for s in prog]


def test_folding_shows_up_as_splices_not_as_lost_statements():
    from pathlib import Path

    from tbx import decode0

    corpus = Path(__file__).resolve().parents[1] / "fixtures" / "corpus"
    prog = decode0.decode_user_code((corpus / "t1_ifblockselect.exe").read_bytes())

    kinds = {e.kind for e in prog.statement_edits}
    assert "append" in kinds
    # A block IF rewrites a region of the list rather than appending to it.
    assert "splice" in kinds
