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

Every way a statement can reach the program is an event kind. Most are
committed by the walk; a revision supersedes one already committed, when a
second runtime call completes it; a reconstruction is derived by finalization
from a layout or pool fact, with no code behind it at all. A statement that
arrives by none of these is a decision the log cannot account for, which is
what the reconciliation exists to expose.
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
    #: The calibrated template the handler matched. Recognition; the construct
    #: is a separate judgement derived from it by `control_graph.frame_for`.
    template: str = ""
    #: Physical address the branch goes to, or None when the construct's exit
    #: is not yet known at recognition time (a SELECT header, whose END SELECT
    #: is only resolved once its arms close).
    target: int | None = None
    cond: Any = None
    #: True when the bytes say the source spelled this IF as a multi-line
    #: block. A simple condition that materialized is positive evidence of it
    #: -- a single-line `IF <simple> THEN <stmt>` compiles a bare dispatch pair
    #: instead -- and the fold needs it to choose the block form. The walk
    #: keeps the same fact in `block_if_addrs`; recording it here is what lets
    #: a pass reading only the log make the same choice.
    block: bool = False


@dataclass(frozen=True)
class RegionEvent:
    """The extent of a construct that owns a span of code.

    A procedure's epilogue is a boundary no statement address describes --
    `END SUB` carries no line number -- yet an inline IF closing a SUB body
    folds up to exactly there. Recording the extent gives that boundary a name.
    """

    kind: str
    start: int | None
    end: int | None
    #: What the recognizer knew about this construct that its extent does not
    #: capture, and that a pass rebuilding the construct would otherwise have
    #: to re-derive: a `case_arm`'s guards, as the tuple of `CaseValue`,
    #: `CaseRange` and `CaseIs` it matched on, and a `select`'s selector
    #: expression. A `proc`, `fn` or `case_else` region has nothing to add --
    #: the extent is the whole of what was recognised -- so it stays None.
    detail: Any = None


@dataclass(frozen=True)
class PatchEvent:
    """A statement the decoder revised after committing it.

    Some statements are compiled as two runtime calls: a LOCATE gains its
    cursor argument from a call that arrives after the row/column one, a FOR's
    provisional step is corrected by NEXT-side evidence, a second DIM on one
    source line joins the first as a comma list. The handler rewrites the
    committed statement in place.

    A revision is not a new statement -- it replaces one already in the list,
    so it names the commit it supersedes rather than standing alone. Replay
    applies it in place; treating it as a commit would grow the program by one
    statement per patch.
    """

    #: ``seq`` of the event this revises: a commit, or an earlier revision of
    #: it (LOCATE takes a cursor call and then a cursor-shape call).
    supersedes: int
    statement: Any


@dataclass(frozen=True)
class ReconstructedEvent:
    """A statement finalization derived rather than decoded.

    DIM, DATA, OPTION BASE, COMMON and DEFtype are recovered from array
    bookkeeping records, the data pool and the error-trap line table. No byte
    pattern was decoded for them and none ever will be -- they own no code, so
    they own no address either.

    A reconstruction is not a commit. Finalization runs after folding, so the
    position it inserts at describes the finished program, not the walk, and
    replaying it into the walk's list would put it somewhere meaningless. What
    the event provides is an account: the statement is in the program because
    a layout fact says so, not because something is missing from the log.
    """

    statement: Any


@dataclass(frozen=True)
class ArrivalEvent:
    """Decoding reached an address that a recorded branch targets.

    A region's start is a position and can be counted; its end is a *moment*.
    Where an inline-IF body ends is the statement list's length when decoding
    gets to the branch's target, and no address describes that instant -- the
    target may be a procedure epilogue or an arm-close jmp, which own no
    statement, and even when a statement does own it an earlier fold has
    already moved where it sits.

    Recording the arrival puts that instant in the same ordered log as the
    edits, so the length is read rather than inferred. The address is one the
    log already knows a branch wants; nothing here is taken from the frame
    bookkeeping the handlers keep.
    """

    address: int


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
    #: Statement indices finalization derived from a layout or pool fact. Told
    #: apart from ``synthesized`` deliberately: a folded statement is built
    #: out of committed ones, while a reconstructed one was never decoded at
    #: all, and counting the two together makes both numbers meaningless.
    reconstructed: tuple[int, ...] = ()

    @property
    def clean(self) -> bool:
        """True when folding left every committed statement where it was.

        A reconstruction does not count against it: the program has that
        statement because a layout fact says so, and an event says as much.
        """
        return not (self.absorbed or self.rewritten or self.synthesized)


@dataclass
class EventLog:
    """Append-only record of committed statements, in emission order."""

    events: list[DecodedEvent] = field(default_factory=list)
    #: Addresses something in the log is waiting for -- a branch's target, a
    #: region's end -- and those already arrived at. Derived from the log's own
    #: contents: an arrival is only interesting where something wants it.
    _wanted: set[int] = field(default_factory=set, repr=False, compare=False)
    _arrived: set[int] = field(default_factory=set, repr=False, compare=False)

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
        self,
        frame: str,
        *,
        template: str,
        target: int | None,
        address: int | None,
        cond: Any = None,
        block: bool = False,
    ) -> DecodedEvent:
        """Record a recognised branch. The statement list is not touched."""
        event = DecodedEvent(
            kind="branch",
            address=address,
            payload=BranchEvent(frame, template, target, cond, block),
            seq=len(self.events),
        )
        self.events.append(event)
        if target is not None:
            self._wanted.add(target)
        return event

    def reconstruct(self, statement: Any) -> DecodedEvent:
        """Record a statement finalization derived from a layout fact."""
        event = DecodedEvent(
            kind="reconstruct",
            address=None,  # codeless: it owns no code and borrows no address
            payload=ReconstructedEvent(statement),
            seq=len(self.events),
        )
        self.events.append(event)
        return event

    def supersede(self, previous: Any, statement: Any) -> DecodedEvent:
        """Record that ``previous`` was revised into ``statement``.

        The event revised is found by identity, scanning back: the object
        being replaced is the one some earlier event committed, and it is
        alive in the caller's hand while we look. Fail-loud when nothing
        committed it -- a pass revising a statement the log never saw is
        exactly the hole this closes, and it must not pass silently.
        """
        for event in reversed(self.events):
            if event.kind == "statement" and event.payload is previous:
                seq, address = event.seq, event.address
                break
            if event.kind == "patch" and event.payload.statement is previous:
                seq, address = event.seq, event.address
                break
        else:
            raise ValueError("revised a statement that was never committed")
        event = DecodedEvent(
            kind="patch",
            address=address,
            payload=PatchEvent(seq, statement),
            seq=len(self.events),
        )
        self.events.append(event)
        return event

    def arrive(self, address: int | None) -> DecodedEvent | None:
        """Record that decoding reached ``address``, if a branch wants it.

        Silent otherwise, and silent on a second visit: the log is a record of
        moments that matter to some branch, not a trace of every address the
        walk passes through. Returns the event, or None when nothing was
        recorded.
        """
        if address is None or address not in self._wanted:
            return None
        if address in self._arrived:
            return None
        self._arrived.add(address)
        event = DecodedEvent(
            kind="arrive",
            address=address,
            payload=ArrivalEvent(address),
            seq=len(self.events),
        )
        self.events.append(event)
        return event

    def region(
        self, kind: str, *, start: int | None, end: int | None, detail: Any = None
    ) -> DecodedEvent:
        """Record a construct's extent. The statement list is not touched."""
        event = DecodedEvent(
            kind="region",
            address=start,
            payload=RegionEvent(kind, start, end, detail),
            seq=len(self.events),
        )
        self.events.append(event)
        if end is not None:
            # A region ends at a moment, exactly as a branch's body does, and
            # the moment is what sizes it: how long the statement list was when
            # decoding got there. The end address is usually not a statement
            # and never a branch target -- an arm-close jmp, a procedure
            # epilogue -- so nothing else in the log would ask for it.
            self._wanted.add(end)
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


def committed(events: Iterable[DecodedEvent]) -> tuple[DecodedEvent, ...]:
    """One event per committed statement, carrying its final decoded form.

    A revision does not add a statement, so it collapses onto the commit it
    supersedes: the entry keeps that commit's ``seq`` and address, and takes
    the revised payload. Everything downstream -- replay, reconciliation, the
    graph -- then sees what the decoder ended up deciding rather than its
    first draft.

    Rejecting unknown kinds is deliberate: adding an event kind must update
    this contract instead of silently dropping it.
    """

    order: list[int] = []
    final: dict[int, DecodedEvent] = {}
    root: dict[int, int] = {}
    for event in events:
        if event.kind in ("branch", "region", "arrive"):
            continue  # carries no statement; the control pass consumes it
        if event.kind == "reconstruct":
            continue  # finalization's, not the walk's: it has no position here
        if event.kind == "patch":
            try:
                target = root[event.payload.supersedes]
            except KeyError:
                raise ValueError(
                    f"revision at {event.seq} supersedes no committed statement"
                ) from None
            root[event.seq] = target
            final[target] = DecodedEvent(
                kind="statement",
                address=final[target].address,
                payload=event.payload.statement,
                seq=target,
            )
            continue
        if event.kind != "statement":
            raise ValueError(f"unknown decoded event kind: {event.kind!r}")
        root[event.seq] = event.seq
        final[event.seq] = event
        order.append(event.seq)
    return tuple(final[seq] for seq in order)


def replay_events(events: Iterable[DecodedEvent]) -> tuple[Any, ...]:
    """Replay committed statement events into the next pipeline pass."""

    return tuple(event.payload for event in committed(events))


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
    # no statement, and counting one would report a phantom rewrite. A
    # revision folds onto the commit it supersedes, so each committed
    # statement is one entry, in its final decoded form.
    events = tuple(events)  # walked twice: once for reconstructions, once for commits
    derived = _derived_counts(events)
    events = committed(events)
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
    # A statement no committed event matched is either something folding built
    # out of committed statements, or something finalization derived. The
    # reconstruction events say which, and are consumed one per statement so
    # two DATA blocks with identical items cannot both claim one event.
    synthesized, reconstructed = [], []
    for index in range(len(statements)):
        if index in matched_indices:
            continue
        statement = statements[index]
        if _hashable(statement) and derived.get(statement):
            derived[statement] -= 1
            reconstructed.append(index)
        else:
            synthesized.append(index)

    return EventReconciliation(
        matched=len(events) - len(unmatched),
        absorbed=absorbed,
        rewritten=rewritten,
        synthesized=tuple(synthesized),
        reconstructed=tuple(reconstructed),
    )


def _derived_counts(events: Iterable[DecodedEvent]) -> dict[Any, int]:
    """How many times finalization reconstructed each statement."""
    counts: dict[Any, int] = {}
    for event in events:
        if event.kind != "reconstruct":
            continue
        statement = event.payload.statement
        if _hashable(statement):
            counts[statement] = counts.get(statement, 0) + 1
    return counts


def _hashable(value: Any) -> bool:
    try:
        hash(value)
    except TypeError:
        return False
    return True
