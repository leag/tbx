"""Schema tests for the decoded-event stream.

Emission and reconciliation live in test_event_emission.py; these cover the
record type and the replay contract on their own.
"""

from tbx import ir
from tbx.decode0.events import (
    DecodedEvent,
    EventLog,
    replay_events,
    statement_events,
)


def test_statement_events_are_immutable_and_address_bearing():
    events = statement_events((ir.End(), ir.Goto(0)), (0x10, None))

    assert events == (
        DecodedEvent("statement", 0x10, ir.End(), 0),
        DecodedEvent("statement", None, ir.Goto(0), 1),
    )
    assert events[0].kind == "statement"
    assert events[0].address == 0x10
    # A codeless statement keeps an absent address rather than borrowing one.
    assert events[1].address is None
    assert replay_events(events) == (ir.End(), ir.Goto(0))


def test_statement_events_number_the_stream_in_order():
    events = statement_events((ir.End(),) * 3, (0x10, 0x20, 0x30))

    assert [e.seq for e in events] == [0, 1, 2]


def test_replay_rejects_unknown_event_kinds():
    try:
        replay_events((DecodedEvent("future", None, ir.End(), 0),))
    except ValueError as exc:
        assert "unknown decoded event kind" in str(exc)
    else:
        raise AssertionError("unknown event kind was silently discarded")


def test_event_log_numbers_commits_in_order():
    log = EventLog()

    log.commit(ir.End(), 0x10)
    log.commit(ir.Goto(0), None)

    assert [e.seq for e in log.frozen()] == [0, 1]
    assert log.frozen()[1].address is None


def test_event_log_frozen_is_a_snapshot_not_a_live_view():
    log = EventLog()
    log.commit(ir.End(), 0x10)

    snapshot = log.frozen()
    log.commit(ir.Goto(0), 0x20)

    assert len(snapshot) == 1
