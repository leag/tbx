"""Events recorded as statements are committed, before control-flow folding.

The Chapter 5 event stream has to be lossless with respect to what the decoder
actually decided, which means recording at commit time with the physical
address still unresolved. Folding runs afterwards and rewrites the statement
list in place, so the event log and the final program deliberately differ --
`reconcile` is what measures that difference instead of hiding it.
"""

from pathlib import Path

from tbx import decode0, ir
from tbx.decode0.core import DecodeState
from tbx.decode0.events import DecodedEvent, reconcile


FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "corpus"


def _exe(name):
    return (FIXTURES / name).read_bytes()


def test_put_records_a_commit_event_with_the_unresolved_address():
    state = DecodeState()
    state.stmts, state.addrs = [], []

    state.put(ir.End(), 0x1234)

    assert state.events == (
        DecodedEvent(kind="statement", address=0x1234, payload=ir.End(), seq=0),
    )


def test_commit_events_keep_emission_order_and_sequence():
    state = DecodeState()
    state.stmts, state.addrs = [], []

    state.put(ir.Goto(("addr", 0x40)), 0x10)
    state.put(ir.End(), 0x20)

    assert [e.seq for e in state.events] == [0, 1]
    assert [e.address for e in state.events] == [0x10, 0x20]


def test_a_codeless_statement_records_an_absent_address():
    # A DATA statement owns no code, so it commits with no physical address.
    # That has to stay absent rather than be filled in with a neighbour's.
    state = DecodeState()
    state.stmts, state.addrs = [], []

    state.put(ir.Data((ir.DataItem("1", False),)), None)

    assert state.events[0].address is None


def test_reconcile_reports_a_clean_match_when_nothing_folded():
    events = (
        DecodedEvent("statement", 0x10, ir.End(), 0),
        DecodedEvent("statement", 0x20, ir.Goto(3), 1),
    )

    report = reconcile(events, [ir.End(), ir.Goto(3)])

    assert report.matched == 2
    assert report.absorbed == ()
    assert report.synthesized == ()
    assert report.clean is True


def test_reconcile_names_statements_folding_absorbed():
    # An inline IF folds its body statement out of the top-level list.
    events = (
        DecodedEvent("statement", 0x10, ir.IfGoto(ir.Lit(1), 2), 0),
        DecodedEvent("statement", 0x20, ir.End(), 1),
    )

    report = reconcile(events, [ir.IfInline(ir.Lit(1), (ir.End(),))])

    # The End moved into the IfInline body; the IfGoto header was rewritten
    # into the structured form, so it is gone rather than nested.
    assert report.absorbed == (1,)
    assert report.rewritten == (0,)
    assert report.synthesized == (0,)
    assert report.clean is False


def test_decoded_program_carries_the_commit_time_event_log():
    prog = decode0.decode_user_code(_exe("t1_print2.exe"))

    assert prog.events
    assert all(e.kind == "statement" for e in prog.events)
    assert [e.seq for e in prog.events] == list(range(len(prog.events)))


def test_commit_events_precede_folding_for_a_real_program():
    # The event log is what the decoder committed; the program is what folding
    # left. For a program with structured control flow the two differ, and the
    # reconciliation is what says how.
    prog = decode0.decode_user_code(_exe("t1_if.exe"))

    assert prog.event_reconciliation is not None
    assert prog.event_reconciliation.matched >= 0
    # Every committed event is accounted for: matched, or absorbed by a fold.
    report = prog.event_reconciliation
    accounted = report.matched + len(report.absorbed) + len(report.rewritten)
    assert accounted == len(prog.events)


# The five shapes Chapter 5 asks for event-level coverage of. Each records
# what the commit-time log says about that shape, so a change in where the
# decoder commits a statement shows up here as a diff rather than silently.


def test_ordinary_statements_reconcile_cleanly():
    prog = decode0.decode_user_code(_exe("t1_print2.exe"))

    assert prog.event_reconciliation.clean is True


def test_a_branch_program_reconciles_cleanly_when_nothing_folds():
    prog = decode0.decode_user_code(_exe("t1_if.exe"))

    assert prog.event_reconciliation.clean is True


def test_a_block_if_absorbs_its_body_into_the_structured_form():
    prog = decode0.decode_user_code(_exe("t1_ifblockselect.exe"))
    report = prog.event_reconciliation

    # Folding moved body statements inside the structured IF, so they are no
    # longer top level -- but they are still in the program.
    assert report.absorbed
    assert report.clean is False


def test_codeless_data_statements_are_synthesized_not_committed():
    """A known gap: DATA never reaches the commit-time log.

    Codeless DATA statements are inserted by finalization from the data pool,
    not committed through `put`, so no event describes them and reconciliation
    reports them as synthesized. The event stream is therefore NOT yet
    lossless -- this pins the gap so it fails when DATA moves onto the event
    path, which Chapter 6 needs before replay can be authoritative.
    """
    from tbx import ir

    prog = decode0.decode_user_code(_exe("t1_dataorph.exe"))

    data_indices = [i for i, s in enumerate(prog) if isinstance(s, ir.Data)]
    assert data_indices, "fixture should contain DATA statements"
    assert not [e for e in prog.events if isinstance(e.payload, ir.Data)]
    assert set(data_indices) <= set(prog.event_reconciliation.synthesized)
