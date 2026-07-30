"""Handlers record the branches they recognise, even when they fold them.

A handler that opens an inline-IF frame has recognised a branch and decided
its construct in one step, committing nothing. The graph cannot see that
decision, so control-flow recovery cannot check it.

Emitting a branch event is the first half of separating the two: the handler
says "there is a branch here, targeting there" without the statement list
changing at all. Moving the *decision* out of the handler comes after, and can
then be verified against these events.
"""

from pathlib import Path

from tbx import decode0, ir
from tbx.decode0.control_graph import ControlGraph
from tbx.decode0.events import BranchEvent, EventLog

CORPUS = Path(__file__).resolve().parents[1] / "fixtures" / "corpus"


def test_the_log_records_a_branch_without_a_statement():
    log = EventLog()

    log.branch(
        "if", template="inline_if_target", target=0x40, address=0x10,
        cond=ir.Lit(1),
    )

    (event,) = log.frozen()
    assert event.kind == "branch"
    assert event.address == 0x10
    assert event.payload == BranchEvent(
        "if", "inline_if_target", 0x40, ir.Lit(1)
    )


def test_branch_and_statement_events_share_one_ordering():
    log = EventLog()

    log.commit(ir.End(), 0x10)
    log.branch("if", template="inline_if_target", target=0x40, address=0x20)
    log.commit(ir.Goto(1), 0x30)

    assert [e.seq for e in log.frozen()] == [0, 1, 2]
    assert [e.kind for e in log.frozen()] == ["statement", "branch", "statement"]


def test_an_inline_if_frame_records_its_branch():
    # `t1_ifgoto` is NOT this case: a plain IF...GOTO commits its branch as a
    # statement, so there is no invisible decision to record. An inline-IF
    # frame is the case that used to be invisible.
    prog = decode0.decode_user_code((CORPUS / "t1_boolflags.exe").read_bytes())

    branches = [e for e in prog.events if e.kind == "branch"]
    assert branches, "an inline IF opens a frame, which is a recognised branch"
    assert all(isinstance(e.payload, BranchEvent) for e in branches)
    assert {e.payload.frame for e in branches} == {"if"}


def test_a_head_tested_loop_records_its_branch():
    prog = decode0.decode_user_code((CORPUS / "t1_whileinstat.exe").read_bytes())

    frames = {e.payload.frame for e in prog.events if e.kind == "branch"}
    assert "loop" in frames


def test_a_program_that_folds_every_branch_still_records_them():
    # The case that had no committed branch at all: block IF plus SELECT CASE,
    # both folded inside the handlers.
    prog = decode0.decode_user_code((CORPUS / "t1_ifblockselect.exe").read_bytes())

    assert [e for e in prog.events if e.kind == "branch"]


def test_recorded_branches_reach_the_graph():
    prog = decode0.decode_user_code((CORPUS / "t1_ifblockselect.exe").read_bytes())

    graph = ControlGraph.from_events(prog.events)

    assert graph.edges


def test_branch_events_do_not_change_the_statement_list():
    """The whole point of emitting rather than committing.

    If recording a branch added a statement, every fixture golden would move.
    """
    prog = decode0.decode_user_code((CORPUS / "t1_boolflags.exe").read_bytes())

    statements = [e for e in prog.events if e.kind == "statement"]
    commits = [
        e
        for e in prog.statement_edits
        if e.kind == "append" and e.origin is None
    ]
    assert len(statements) == len(commits)


def test_reconciliation_ignores_branch_events():
    # Reconciliation relates committed statements to the folded list. A branch
    # event has no statement, so counting it as one would report a phantom
    # rewrite.
    prog = decode0.decode_user_code((CORPUS / "t1_ifgoto.exe").read_bytes())

    report = prog.event_reconciliation
    statements = [e for e in prog.events if e.kind == "statement"]
    accounted = report.matched + len(report.absorbed) + len(report.rewritten)
    assert accounted == len(statements)
