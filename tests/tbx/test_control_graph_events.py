"""The control graph, built from what the decoder committed.

`ControlGraph.from_statements` reads the finished program: by then folding has
already decided every branch, so the graph can only confirm what happened.
Building from commit-time events instead puts the graph before those
decisions, with targets still unresolved — which is the order Chapter 6 needs.

Classification says what became of each branch and which pass decided it. The
edit log is the ground truth: a branch that folding rewrote is attributed to
the pass that rewrote it, not guessed at from the branch's shape.
"""

from pathlib import Path

from tbx import decode0, ir
from tbx.decode0.control_graph import ControlGraph, classify_branches
from tbx.decode0.events import DecodedEvent

CORPUS = Path(__file__).resolve().parents[1] / "fixtures" / "corpus"


def _events(*pairs):
    return tuple(
        DecodedEvent("statement", address, payload, seq)
        for seq, (address, payload) in enumerate(pairs)
    )


def test_graph_from_events_keeps_unresolved_addresses():
    events = _events(
        (0x10, ir.IfGoto(ir.Lit(1), ("addr", 0x20))),
        (0x20, ir.End()),
    )

    graph = ControlGraph.from_events(events)

    assert graph.nodes[0].address == 0x10
    edge = graph.outgoing(0)[0]
    assert edge.target == 0x20
    graph.validate_targets()


def test_graph_from_events_rejects_a_target_no_event_owns():
    events = _events((0x10, ir.IfGoto(ir.Lit(1), ("addr", 0x99))))

    graph = ControlGraph.from_events(events)

    try:
        graph.validate_targets()
    except ValueError as exc:
        assert "0x99" in str(exc)
    else:
        raise AssertionError("an unowned jump target must stay fail-loud")


def test_resolve_maps_an_address_to_the_event_that_owns_it():
    events = _events(
        (0x10, ir.Goto(("addr", 0x30))),
        (0x20, ir.End()),
        (0x30, ir.End()),
    )

    graph = ControlGraph.from_events(events)

    assert graph.resolve(0x30) == 2
    assert graph.resolve(0x99) is None


def test_a_codeless_event_owns_no_address():
    # A DATA statement commits unaddressed and must not become a jump target.
    events = _events((None, ir.Data(())), (0x10, ir.End()))

    graph = ControlGraph.from_events(events)

    assert graph.nodes[0].address is None
    assert graph.resolve(None) is None


def test_classify_reports_a_branch_that_stayed_a_raw_jump():
    prog = decode0.decode_user_code((CORPUS / "t1_ifgoto.exe").read_bytes())

    report = classify_branches(prog)

    assert report
    assert all(b.outcome in ("raw", "folded", "absorbed") for b in report)
    assert any(b.outcome == "raw" for b in report), (
        "t1_ifgoto's branch survives as an IfGoto, so it should classify raw"
    )


def test_classify_attributes_a_folded_branch_to_the_pass_that_folded_it():
    prog = decode0.decode_user_code((CORPUS / "t1_ifgoto.exe").read_bytes())

    report = classify_branches(prog)
    folded = [b for b in report if b.outcome != "raw"]

    assert folded
    assert all(b.decided_by is not None for b in folded), (
        "a folded branch names the pass responsible, taken from the edit log"
    )
    assert {b.decided_by for b in folded} == {"close_ifs"}


def test_some_structure_is_built_from_branches_that_never_commit():
    """The remaining blind spot, pinned deliberately.

    Inline-IF frames, SELECT headers and head-tested loops now record a branch
    event, which took the corpus from 103 fixtures the graph could not see
    down to 40. `t1_fnblockif` is one of the 40: it ends up with structure and
    uses `close_ifs`, yet records neither a committed branch nor a branch
    event, so some frame still opens by a path that does not announce itself.

    This fails once that path is found, which is the signal the graph can
    take over.
    """
    prog = decode0.decode_user_code((CORPUS / "t1_fnblockif.exe").read_bytes())

    assert any(isinstance(s, (ir.IfBlock, ir.IfInline)) for s in _walk(prog))
    assert classify_branches(prog) == ()
    assert not [e for e in prog.events if e.kind == "branch"]


def _walk(statements):
    for s in statements:
        yield s
        for name in getattr(s, "__dataclass_fields__", ()):
            value = getattr(s, name)
            if isinstance(value, tuple):
                yield from _walk(value)


def test_every_branch_is_classified_for_a_real_program():
    prog = decode0.decode_user_code((CORPUS / "t1_if.exe").read_bytes())

    report = classify_branches(prog)
    branches = [e for e in prog.events if _has_addr_target(e.payload)]

    assert len(report) == len(branches)


def _has_addr_target(value):
    from dataclasses import fields, is_dataclass

    if isinstance(value, tuple) and len(value) == 2 and value[0] == "addr":
        return True
    if is_dataclass(value):
        return any(_has_addr_target(getattr(value, f.name)) for f in fields(value))
    if isinstance(value, (tuple, list)):
        return any(_has_addr_target(v) for v in value)
    return False
