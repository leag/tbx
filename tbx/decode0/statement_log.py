"""A statement list that records every edit made to it.

Statements reach the decoder's output by more paths than ``put``: pending
chains flush directly, handlers patch an already-committed statement in place,
folding deletes and inserts, and finalization reconstructs DIM/DATA from
layout facts. Recording at each call site means remembering to, at twenty of
them, forever.

So the list records itself. :func:`replay` rebuilding the exact final list is
the losslessness property: an edit that skipped the recorder would make replay
diverge, and the decode-time check says so.

The log is deliberately about *what happened to the list*, not about what it
means. Interpreting an edit as a fold, a patch, or a reconstruction is the
control-flow pass's job.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class StatementEdit:
    """One recorded change to the statement list.

    ``origin`` names the pass that made the change -- which is what tells a
    fold apart from a handler patch or a declaration reconstructed from layout
    facts. It is ``None`` for an ordinary decode-time commit.
    """

    kind: str
    index: int | None = None
    stop: int | None = None
    payload: tuple[Any, ...] = ()
    origin: str | None = None
    #: How many decoded events had been recorded when this edit was made.
    #: Without it the edit log and the event log cannot be interleaved, and
    #: "how long was the list when that branch was recognised" is unanswerable.
    at_event: int = 0


class RecordedStatements(list):
    """A ``list`` of statements that appends a :class:`StatementEdit` per change.

    Only the mutating operations the decoder actually uses are recorded.
    Anything else would silently bypass the log, so the unsupported mutators
    raise rather than pretend.
    """

    def __init__(self, initial=()):
        initial = list(initial)
        super().__init__(initial)
        self.edits: list[StatementEdit] = []
        self.origin: str | None = None
        #: Supplies the current event count; the default keeps a bare list
        #: usable in unit tests that have no event log.
        self.clock = lambda: 0
        if initial:
            self.edits.append(StatementEdit("reset", payload=tuple(initial)))

    def append(self, statement) -> None:
        super().append(statement)
        self._record("append", payload=(statement,))

    def insert(self, index, statement) -> None:
        super().insert(index, statement)
        self._record("insert", index=self._absolute(index), payload=(statement,))

    def pop(self, index=-1):
        absolute = self._absolute(index)
        statement = super().pop(index)
        self._record("delete", index=absolute)
        return statement

    def __setitem__(self, index, value) -> None:
        if isinstance(index, slice):
            start, stop, step = index.indices(len(self))
            if step != 1:
                raise ValueError("recorded statements do not support strided writes")
            super().__setitem__(index, value)
            self._record("splice", index=start, stop=stop, payload=tuple(value))
            return
        absolute = self._absolute(index)
        super().__setitem__(index, value)
        self._record("replace", index=absolute, payload=(value,))

    def __delitem__(self, index) -> None:
        if isinstance(index, slice):
            start, stop, step = index.indices(len(self))
            if step != 1:
                raise ValueError("recorded statements do not support strided deletes")
            super().__delitem__(index)
            self._record("splice", index=start, stop=stop)
            return
        absolute = self._absolute(index)
        super().__delitem__(index)
        self._record("delete", index=absolute)

    def extend(self, statements) -> None:
        for statement in statements:
            self.append(statement)

    def _record(self, kind, **detail) -> None:
        self.edits.append(
            StatementEdit(
                kind, origin=self.origin, at_event=self.clock(), **detail
            )
        )

    def _absolute(self, index: int) -> int:
        return index + len(self) if index < 0 else index

    # Mutators the decoder does not use; recording them was never designed, so
    # they must not silently pass through unrecorded.
    def _unsupported(self, *_args, **_kwargs):
        raise TypeError("this mutation is not recorded by RecordedStatements")

    remove = sort = reverse = clear = _unsupported


@contextmanager
def editing(statements, origin: str):
    """Attribute every edit made inside this block to ``origin``.

    Scoped rather than passed as an argument: a pass declares itself once, at
    its own entry, instead of every call site remembering to label. A plain
    list is accepted and ignored, so lift helpers stay callable with one in
    unit tests.
    """
    if not isinstance(statements, RecordedStatements):
        yield
        return
    previous = statements.origin
    statements.origin = origin
    try:
        yield
    finally:
        statements.origin = previous


def replay(edits) -> list:
    """Rebuild the statement list from its recorded edits."""
    statements: list = []
    for edit in edits:
        if edit.kind == "reset":
            statements = list(edit.payload)
        elif edit.kind == "append":
            statements.append(edit.payload[0])
        elif edit.kind == "insert":
            statements.insert(edit.index, edit.payload[0])
        elif edit.kind == "replace":
            statements[edit.index] = edit.payload[0]
        elif edit.kind == "delete":
            del statements[edit.index]
        elif edit.kind == "splice":
            statements[edit.index : edit.stop] = list(edit.payload)
        else:
            raise ValueError(f"unknown statement edit: {edit.kind!r}")
    return statements
