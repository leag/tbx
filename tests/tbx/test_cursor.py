"""Tests for the decoder's compatibility operation cursor."""

import pytest

from tbx.decode0.cursor import CursorError, DecodeDiagnostics, OpCursor
from tbx.decode0.core import DecodeState


OPS = ((0x10, "first", 1), (0x20, "second", 2), (0x30, "third", 3))


def test_cursor_peek_take_expect_and_history():
    cursor = OpCursor(OPS)

    assert cursor.peek() == OPS[0]
    assert cursor.expect("first", 1) == OPS[0]
    assert cursor.peek() == OPS[1]
    assert cursor.take() == OPS[1]
    assert cursor.history == [OPS[0], OPS[1]]


def test_cursor_mark_rewind_and_window():
    cursor = OpCursor(OPS)
    mark = cursor.mark()
    cursor.take()
    assert cursor.window(cursor.index) == ()
    cursor.rewind(mark)
    assert cursor.index == 0


def test_cursor_rejects_invalid_consumption():
    cursor = OpCursor(OPS)
    with pytest.raises(CursorError):
        cursor.peek(3)
    with pytest.raises(CursorError):
        cursor.expect("wrong")
    with pytest.raises(CursorError):
        cursor.sync(-1)


def test_cursor_sync_records_legacy_consumption():
    cursor = OpCursor(OPS)
    cursor.sync(2)
    assert cursor.index == 2
    assert cursor.history == [OPS[0], OPS[1]]


def test_advance_and_seek_commit_the_same_window():
    relative, absolute = DecodeState(), DecodeState()
    for state in (relative, absolute):
        state.k = 0
        state.cursor = OpCursor(OPS)

    relative.advance(2)
    absolute.seek(2)

    assert relative.k == absolute.k == 2
    assert relative.cursor.index == absolute.cursor.index == 2
    # Both paths must record the crossed operations, not just the endpoint:
    # the diagnostic history is what explains a later mismatch.
    assert relative.cursor.history == absolute.cursor.history == [OPS[0], OPS[1]]


def test_seek_refuses_to_uncommit_consumed_operations():
    state = DecodeState()
    state.k = 0
    state.cursor = OpCursor(OPS)
    state.advance(2)

    with pytest.raises(CursorError, match="moved backwards"):
        state.seek(1)

    # The rejected seek must not have moved anything.
    assert state.k == state.cursor.index == 2
    state.seek(3)
    assert state.cursor.history == list(OPS)


def test_diagnostics_report_has_replay_context():
    cursor = OpCursor(OPS)
    cursor.sync(2)
    diagnostics = DecodeDiagnostics(component="expression")
    diagnostics.observe(cursor, address=0x1234, statement=0x1200)
    report = diagnostics.report()
    assert "phase=lift" in report
    assert "offset=0x1234" in report
    assert "op=2" in report
    assert "component=expression" in report
    assert "recent=" in report


def test_decode_state_views_alias_legacy_storage():
    # The ownership partition itself is covered by test_state_parts.py; this
    # only pins that a cursor-carrying state still exposes live aliases.
    state = DecodeState()
    state.ax = 7
    state.stack = []
    state.stack.append("value")
    state.cur = 0x40

    assert state.machine.ax == 7
    assert state.expr.stack == ["value"]
    assert state.control.cur == 0x40
    assert state.output.stmts is state.stmts
    assert state.output.addrs is state.addrs

    state.machine.ax = 9
    state.control.cur = 0x50
    assert state.ax == 9
    assert state.cur == 0x50


def test_decode_state_error_keeps_fail_loud_message_and_adds_context():
    state = DecodeState()
    state.diagnostics = DecodeDiagnostics(file_offset=0x20, op_index=3)

    error = state.error("unknown template", component="expression")

    assert isinstance(error, ValueError)
    assert str(error).startswith("unknown template [phase=lift")
    assert "component=expression" in str(error)


def test_decode_state_ownership_validation():
    state = DecodeState()
    state.validate_ownership()
    state.expr = None
    with pytest.raises(ValueError, match="view 'expr' is detached"):
        state.validate_ownership()
