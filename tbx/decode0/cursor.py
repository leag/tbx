"""Explicit operation consumption primitives used by the decoder migration.

The legacy decoder still owns its position in ``DecodeState.k``.  ``OpCursor``
is therefore deliberately an adapter for now: it observes that position,
records the consumed window, and provides a safe API for newly migrated
handlers.  It does not silently advance the legacy loop.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable


class CursorError(ValueError):
    """Raised when an operation cursor is used outside its valid window."""


@dataclass(frozen=True)
class CursorMark:
    """A local position to which a cursor may rewind."""

    index: int


@dataclass
class OpCursor:
    """Bounded view over an operation stream.

    ``index`` is the next operation to consume.  ``sync`` is the compatibility
    bridge for the old loop: it imports a legacy ``k`` value and records all
    operations crossed since the previous synchronization point.
    """

    ops: tuple[tuple[Any, ...], ...] | list[tuple[Any, ...]]
    index: int = 0
    history_limit: int = 16
    history: list[tuple[Any, ...]] = field(default_factory=list)
    _mark_floor: int = 0

    def __post_init__(self) -> None:
        self.ops = tuple(self.ops)
        self._check_index(self.index)

    def _check_index(self, index: int) -> None:
        if not 0 <= index <= len(self.ops):
            raise CursorError(f"operation cursor out of bounds: {index}")

    @property
    def at_end(self) -> bool:
        return self.index == len(self.ops)

    def peek(self, offset: int = 0) -> tuple[Any, ...]:
        pos = self.index + offset
        if not 0 <= pos < len(self.ops):
            raise CursorError(f"operation peek out of bounds: {pos}")
        return self.ops[pos]

    def take(self) -> tuple[Any, ...]:
        op = self.peek()
        self.index += 1
        self._record((op,))
        return op

    def expect(self, kind: str, *operands: Any) -> tuple[Any, ...]:
        op = self.peek()
        if len(op) < 2 or op[1] != kind or any(
            expected is not None
            and (2 + n >= len(op) or op[2 + n] != expected)
            for n, expected in enumerate(operands)
        ):
            raise CursorError(
                f"expected {kind}{operands!r} at {op[0] if op else self.index:#x};"
                f" got {op!r}"
            )
        return self.take()

    def mark(self) -> CursorMark:
        self._mark_floor = self.index
        return CursorMark(self.index)

    def rewind(self, mark: CursorMark) -> None:
        if not isinstance(mark, CursorMark):
            raise CursorError("invalid operation cursor mark")
        if mark.index < self._mark_floor or mark.index > self.index:
            raise CursorError(f"cannot rewind cursor to {mark.index}")
        self.index = mark.index

    def window(self, stop: int) -> tuple[tuple[Any, ...], ...]:
        self._check_index(stop)
        if stop < self.index:
            raise CursorError(f"operation window reverses cursor: {self.index}->{stop}")
        return self.ops[self.index : stop]

    def sync(self, legacy_index: int) -> None:
        """Import a legacy loop position and record the crossed operations."""

        self._check_index(legacy_index)
        if legacy_index < self.index:
            # A legacy handler may use a local lookahead convention, but the
            # top-level decoder is not allowed to commit a backwards move.
            raise CursorError(
                f"legacy operation index moved backwards: {self.index}->{legacy_index}"
            )
        self._record(self.ops[self.index : legacy_index])
        self.index = legacy_index

    def _record(self, items: Iterable[tuple[Any, ...]]) -> None:
        self.history.extend(items)
        if len(self.history) > self.history_limit:
            del self.history[: -self.history_limit]


@dataclass
class DecodeDiagnostics:
    """Bounded, observational context for a decoder failure report."""

    phase: str = "lift"
    file_offset: int | None = None
    op_index: int | None = None
    statement_address: int | None = None
    component: str | None = None
    expected: list[str] = field(default_factory=list)
    rejected: list[str] = field(default_factory=list)
    history: list[tuple[Any, ...]] = field(default_factory=list)

    def observe(self, cursor: OpCursor, *, address: int | None, statement: int | None) -> None:
        self.op_index = cursor.index
        self.file_offset = address
        self.statement_address = statement
        self.history = list(cursor.history)

    def report(self) -> str:
        parts = [f"phase={self.phase}"]
        if self.file_offset is not None:
            parts.append(f"offset={self.file_offset:#x}")
        if self.op_index is not None:
            parts.append(f"op={self.op_index}")
        if self.statement_address is not None:
            parts.append(f"statement={self.statement_address:#x}")
        if self.component:
            parts.append(f"component={self.component}")
        if self.history:
            parts.append(f"recent={self.history!r}")
        if self.expected:
            parts.append(f"expected={self.expected!r}")
        if self.rejected:
            parts.append(f"rejected={self.rejected!r}")
        return ", ".join(parts)
