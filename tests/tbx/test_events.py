from tbx import ir
from tbx.decode0.events import DecodedEvent, replay_events, statement_events


def test_statement_events_are_immutable_and_address_bearing():
    events = statement_events((ir.End(), ir.Goto(0)), (0x10, None))

    assert events == (
        DecodedEvent("statement", 0x10, ir.End()),
        DecodedEvent("statement", None, ir.Goto(0)),
    )
    assert events[0].kind == "statement"
    assert events[0].address == 0x10
    assert replay_events(events) == (ir.End(), ir.Goto(0))


def test_replay_rejects_unknown_event_kinds():
    try:
        replay_events((DecodedEvent("future", None, ir.End()),))
    except ValueError as exc:
        assert "unknown decoded event kind" in str(exc)
    else:
        raise AssertionError("unknown event kind was silently discarded")
