"""Address-bearing events recorded as the decoder commits statements.

An event is written when a statement is committed, with its physical address
still unresolved. Control-flow folding runs afterwards and rewrites the
statement list in place -- deleting statements it absorbs into a body,
inserting synthesized headers, replacing a branch with the structured form.
So the event log and the final program are *expected* to differ.

:func:`reconcile` measures that difference rather than hiding it. What it
reports is the input the control-flow extraction needs: which committed
statements folding absorbed, and which program statements folding synthesized
with no committed counterpart.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field, fields, is_dataclass
from typing import Any, Iterable


@dataclass(frozen=True)
class DecodedEvent:
    """One decoded, address-bearing statement event.

    ``address`` is the physical address at commit time, unresolved -- ``None``
    for a codeless statement, which owns no code and must not borrow a
    neighbour's address. ``seq`` is the emission order, stable across folding.
    """

    kind: str
    address: int | None
    payload: Any
    seq: int = 0


@dataclass(frozen=True)
class BranchEvent:
    """A branch a handler recognised, whether or not it committed a statement.

    ``frame`` is the construct the handler opened -- "if", "loop", "case",
    "proc". That it is recorded here at all is transitional: separating
    recognition from the construct decision is what lets the control-flow pass
    make that call instead, checked against these events.
    """

    frame: str
    target: int
    cond: Any = None


@dataclass(frozen=True)
class EventReconciliation:
    """How the committed event log relates to the folded statement list.

    The three outcomes are what folding can do to a committed statement, and
    they are worth telling apart: a statement moved into a body is still in
    the program, while a rewritten one is not.
    """

    #: Committed events still standing as top-level statements.
    matched: int = 0
    #: ``seq`` of each event folding moved inside another statement's body.
    absorbed: tuple[int, ...] = ()
    #: ``seq`` of each event folding replaced outright -- an IF header becoming
    #: the structured form, a NEXT collapsing into its FOR.
    rewritten: tuple[int, ...] = ()
    #: Statement indices folding synthesized with no committed counterpart.
    synthesized: tuple[int, ...] = ()

    @property
    def clean(self) -> bool:
        """True when folding left every committed statement where it was."""
        return not (self.absorbed or self.rewritten or self.synthesized)


@dataclass
class EventLog:
    """Append-only record of committed statements, in emission order."""

    events: list[DecodedEvent] = field(default_factory=list)

    def commit(self, statement: Any, address: int | None) -> DecodedEvent:
        event = DecodedEvent(
            kind="statement",
            address=address,
            payload=statement,
            seq=len(self.events),
        )
        self.events.append(event)
        return event

    def branch(
        self, frame: str, *, target: int, address: int | None, cond: Any = None
    ) -> DecodedEvent:
        """Record a recognised branch. The statement list is not touched."""
        event = DecodedEvent(
            kind="branch",
            address=address,
            payload=BranchEvent(frame, target, cond),
            seq=len(self.events),
        )
        self.events.append(event)
        return event

    def frozen(self) -> tuple[DecodedEvent, ...]:
        return tuple(self.events)


def statement_events(
    statements: Iterable[Any], addresses: Iterable[int | None]
) -> tuple[DecodedEvent, ...]:
    """Build an event stream from a finished statement/address pairing."""

    return tuple(
        DecodedEvent("statement", address, statement, seq)
        for seq, (statement, address) in enumerate(
            zip(statements, addresses, strict=True)
        )
    )


def replay_events(events: Iterable[DecodedEvent]) -> tuple[Any, ...]:
    """Replay committed statement events into the next pipeline pass.

    Rejecting unknown kinds is deliberate: adding an event kind must update
    the replay contract instead of silently dropping it.
    """

    statements = []
    for event in events:
        if event.kind == "branch":
            continue  # carries no statement; the control pass consumes it
        if event.kind != "statement":
            raise ValueError(f"unknown decoded event kind: {event.kind!r}")
        statements.append(event.payload)
    return tuple(statements)


def _nested_statements(value: Any) -> set:
    """Every statement reachable inside a folded statement's bodies.

    Unhashable payloads are skipped rather than forced: they cannot be looked
    up here, and the caller reports them as rewritten, which is the
    conservative answer.
    """
    found: set = set()

    def visit(item: Any, top: bool) -> None:
        if is_dataclass(item):
            if not top:
                try:
                    found.add(item)
                except TypeError:
                    pass
            for f in fields(item):
                visit(getattr(item, f.name), False)
        elif isinstance(item, (tuple, list)):
            for child in item:
                visit(child, top)

    visit(value, True)
    return found


def reconcile(
    events: Iterable[DecodedEvent], statements: Iterable[Any]
) -> EventReconciliation:
    """Relate the commit-time event log to the folded statement list.

    Matching is by equality in emission order, not identity: folding rebuilds
    the statements it rewrites, so identity would report every fold as a total
    loss. Order matters because two identical statements can sit at different
    positions -- the walk consumes each position once, so the second cannot
    claim the first's match.

    An event that no longer stands at top level is looked for inside the
    bodies of the statements folding produced. Finding it there means folding
    moved it; not finding it means folding rewrote it.

    Indexed by value rather than scanned: a linear scan per event is
    quadratic, and the largest wild programs commit several thousand
    statements.
    """
    # Only statement events relate to the statement list; a branch event has
    # no statement, and counting one would report a phantom rewrite.
    events = tuple(e for e in events if e.kind == "statement")
    statements = list(statements)

    positions: dict[Any, deque] = {}
    for index, statement in enumerate(statements):
        try:
            positions.setdefault(statement, deque()).append(index)
        except TypeError:  # unhashable: never matched, reported as synthesized
            continue

    matched_indices: set[int] = set()
    unmatched: list[DecodedEvent] = []
    cursor = 0
    for event in events:
        slots = positions.get(event.payload) if _hashable(event.payload) else None
        while slots and slots[0] < cursor:
            slots.popleft()
        if slots:
            index = slots.popleft()
            matched_indices.add(index)
            cursor = index + 1
        else:
            unmatched.append(event)

    bodies: set = set()
    for statement in statements:
        bodies |= _nested_statements(statement)
    absorbed = tuple(
        e.seq for e in unmatched if _hashable(e.payload) and e.payload in bodies
    )
    absorbed_seqs = frozenset(absorbed)
    rewritten = tuple(e.seq for e in unmatched if e.seq not in absorbed_seqs)
    synthesized = tuple(
        index for index in range(len(statements)) if index not in matched_indices
    )

    return EventReconciliation(
        matched=len(events) - len(unmatched),
        absorbed=absorbed,
        rewritten=rewritten,
        synthesized=synthesized,
    )


def _hashable(value: Any) -> bool:
    try:
        hash(value)
    except TypeError:
        return False
    return True
