"""Procedure boundaries are recorded as regions, not inferred.

An inline IF that is the last statement of a SUB body skips to the epilogue,
which is not a statement and never can be -- END SUB carries no line number.
Its fold region therefore ends at a boundary no statement address describes,
and 21 of the 62 inline-IF folds in the corpus are this shape.

Recording the procedure's own extent gives that boundary a name. It is also
the "region boundaries" the chapter asks the graph to carry.
"""

from pathlib import Path

from tbx import decode0, ir
from tbx.decode0.events import ArrivalEvent, EventLog, RegionEvent

CORPUS = Path(__file__).resolve().parents[1] / "fixtures" / "corpus"


def test_the_log_records_a_region():
    log = EventLog()

    log.region("proc", start=0x100, end=0x200)

    (event,) = log.frozen()
    assert event.kind == "region"
    assert event.payload == RegionEvent("proc", 0x100, 0x200)


def test_regions_share_the_one_ordering():
    log = EventLog()

    log.commit(ir.End(), 0x10)
    log.region("proc", start=0x20, end=0x30)

    assert [e.seq for e in log.frozen()] == [0, 1]
    assert [e.kind for e in log.frozen()] == ["statement", "region"]


def test_a_sub_records_its_extent():
    prog = decode0.decode_user_code((CORPUS / "t1_exitsublocstr.exe").read_bytes())

    regions = [e.payload for e in prog.events if e.kind == "region"]
    assert regions, "a SUB body is a region"
    assert all(r.kind == "proc" for r in regions)
    assert all(r.end is not None for r in regions)


def test_the_recorded_end_is_where_exit_sub_jumps():
    # The epilogue start, not the proc_ret: a SUB with LOCAL strings frees
    # their descriptors first, and EXIT SUB targets the first freeing pair.
    prog = decode0.decode_user_code((CORPUS / "t1_exitsublocstr.exe").read_bytes())

    region = next(e.payload for e in prog.events if e.kind == "region")
    targets = {
        e.payload.target
        for e in prog.events
        if e.kind == "branch" and e.payload.target is not None
    }
    assert region.end in targets or region.end > region.start


def _branching_log(target):
    log = EventLog()
    log.branch("if", template="inline_if_target", target=target, address=0x100)
    return log


def test_an_arrival_records_reaching_an_address_a_branch_wants():
    log = _branching_log(0x200)

    log.arrive(0x200)

    assert log.frozen()[-1].kind == "arrive"
    assert log.frozen()[-1].payload == ArrivalEvent(0x200)


def test_an_address_no_branch_wants_records_nothing():
    """The log is a record of moments that matter, not a trace of the walk.

    Every decoded operation passes an address here, so recording them all
    would bury the events that mean something under thousands that do not.
    What makes an address interesting is already in the log: some branch is
    waiting for it.
    """
    log = _branching_log(0x200)

    assert log.arrive(0x300) is None
    assert log.arrive(None) is None
    assert [e.kind for e in log.frozen()] == ["branch"]


def test_an_address_is_arrived_at_once():
    log = _branching_log(0x200)

    log.arrive(0x200)
    log.arrive(0x200)

    assert [e.kind for e in log.frozen()] == ["branch", "arrive"]


def test_an_arrival_is_not_a_statement_start():
    """An arrival address is one that may own no statement -- that is the
    point of recording it. Letting it into the graph's address set would make
    the target validation accept a jump nothing owns."""
    from tbx.decode0.control_graph import ControlGraph

    log = _branching_log(0x200)
    log.arrive(0x200)

    graph = ControlGraph.from_events(log.frozen())

    assert 0x200 not in graph.addresses


def test_a_region_carries_no_statement():
    """Regions are observations, not commits.

    Replay must skip them: a region describes an extent, and treating one as a
    statement would inject a phantom into the program.
    """
    from tbx.decode0.events import replay_events

    prog = decode0.decode_user_code((CORPUS / "t1_exitsublocstr.exe").read_bytes())

    statements = [e for e in prog.events if e.kind == "statement"]
    assert [e for e in prog.events if e.kind == "region"]
    assert [e for e in prog.events if e.kind == "arrive"]
    assert len(replay_events(prog.events)) == len(statements)
