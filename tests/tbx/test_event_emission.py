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


def test_a_flushed_chain_records_its_commit_event():
    """A chain closes late, but it is still a decoder decision.

    A trailing-';' PRINT, an INPUT#/READ target chain and a FIELD list have no
    flush vector: they finalize when the next statement completes, and reach
    the list through `flush_pending` rather than `put`. Committing without an
    event is the one way a statement can enter the program with nothing in the
    log accounting for it -- and a fold whose whole body is such a chain then
    has no record of its own body (wild be.exe).
    """
    prog = decode0.decode_user_code(_exe("t1_fori.exe"))

    flushed = [
        e.payload[0]
        for e in prog.statement_edits
        if e.origin == "flush_pending" and e.kind == "append"
    ]
    assert flushed, "fixture should flush a pending chain"
    committed = [e.payload for e in prog.events if e.kind == "statement"]
    for statement in flushed:
        assert statement in committed


def test_every_statement_in_the_list_comes_from_a_commit():
    """No path reaches the statement list without recording an event.

    Folding still rewrites the list afterwards, so the *program* and the log
    differ by design. What must not differ is the set of statements the
    decoder put there: an append the log never saw is a decision the
    control-flow pass cannot replay.
    """
    from tbx.decode0.statement_log import replay

    missing = []
    for exe in sorted(FIXTURES.glob("*.exe")):
        try:
            prog = decode0.decode_user_code(exe.read_bytes())
        except ValueError:
            continue
        committed = {
            id(e.payload) for e in prog.events if e.kind == "statement"
        }
        for edit in prog.statement_edits:
            if edit.kind != "append" or edit.origin != "flush_pending":
                continue
            if id(edit.payload[0]) not in committed:
                missing.append((exe.name, type(edit.payload[0]).__name__))
        assert replay(prog.statement_edits) is not None
    assert not missing, f"{len(missing)} appends with no event: {missing[:5]}"


#: The decode-time passes that revise an already-committed statement, as
#: opposed to the folding passes that rewrite the list afterwards. A LOCATE
#: gains its cursor argument from a later runtime call; a FOR's provisional
#: step is corrected by NEXT-side evidence; a second DIM on one source line
#: joins the first as a comma list.
_PATCHES = ("patch_locate", "patch_for_step", "dim_declaration")


def test_a_revised_statement_records_its_revision():
    """`LOCATE 5,10,1` is two runtime calls: the second patches the first.

    The row/column call commits an `ir.Locate`; the cursor call arrives after
    and rewrites it in place. Without an event for the revision, the log
    describes a statement the program does not contain and misses the one it
    does.
    """
    prog = decode0.decode_user_code(_exe("t1_loccurs.exe"))

    revised = [
        e.payload[0]
        for e in prog.statement_edits
        if e.kind == "replace" and e.origin == "patch_locate"
    ]
    assert revised, "fixture should patch a LOCATE"
    from tbx.decode0.events import replay_events

    replayed = replay_events(prog.events)
    for statement in revised:
        assert statement in replayed


def test_a_revision_replaces_rather_than_adds():
    """A patch is not a new statement.

    Replay has to apply the revision to the statement already there, or the
    program grows one statement per patch -- which is worse than the gap it
    closes.
    """
    from tbx.decode0.events import replay_events

    prog = decode0.decode_user_code(_exe("t1_loccurs.exe"))

    commits = [e for e in prog.events if e.kind == "statement"]
    assert [e for e in prog.events if e.kind == "patch"]
    assert len(replay_events(prog.events)) == len(commits)


def test_no_decode_time_revision_is_lost_across_the_corpus():
    """Every revised statement is in the replay, in its last decoded form.

    Last per position, because a statement can be revised twice -- `LOCATE`
    takes a cursor call and then a cursor-shape call, and three DIMs on one
    source line join the list one after another. The intermediate drafts are
    supposed to be gone; requiring them back would ask replay to keep
    statements the decoder itself discarded.

    Positions are stable to group by: nothing folds during decoding at the
    index a patch names, so one index means one statement being revised.
    """
    from tbx.decode0.events import replay_events

    missing = []
    for exe in sorted(FIXTURES.glob("*.exe")):
        try:
            prog = decode0.decode_user_code(exe.read_bytes())
        except ValueError:
            continue
        latest = {}
        for edit in prog.statement_edits:
            if edit.kind == "replace" and edit.origin in _PATCHES:
                latest[edit.index] = edit.payload[0]
        if not latest:
            continue
        replayed = replay_events(prog.events)
        for statement in latest.values():
            if statement not in replayed:
                missing.append((exe.name, type(statement).__name__))
    assert not missing, f"{len(missing)} revisions with no event: {missing[:5]}"


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
