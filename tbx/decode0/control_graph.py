"""Address-level control-flow graph for the lifting boundary.

Two constructors, at two points in the pipeline.

:meth:`ControlGraph.from_statements` reads the finished program. By then
folding has decided every branch, so the graph can only confirm what happened.
It stays the validation the legacy resolver runs against.

:meth:`ControlGraph.from_events` reads the commit-time event log, with targets
still unresolved -- the graph *before* those decisions, which is the order
Chapter 6 needs. :func:`classify_branches` then says what became of each
branch and which pass decided it, taken from the statement edit log rather
than inferred from the branch's shape.

Neither constructor folds anything yet. The classification runs alongside the
existing path so the two can be compared branch by branch.
"""

from __future__ import annotations

from dataclasses import dataclass, fields, is_dataclass
from typing import Any, Iterable


@dataclass(frozen=True)
class ControlNode:
    index: int
    address: int | None


@dataclass(frozen=True)
class ControlEdge:
    source: int
    target: int
    kind: str


@dataclass(frozen=True)
class ControlGraph:
    nodes: tuple[ControlNode, ...]
    edges: tuple[ControlEdge, ...]
    addresses: frozenset[int]

    @classmethod
    def from_statements(
        cls,
        statements: Iterable[Any],
        addresses: Iterable[int | None],
        stmt_addr: dict[int, int] | None = None,
    ) -> "ControlGraph":
        statements = tuple(statements)
        addresses = tuple(addresses)
        if len(statements) != len(addresses):
            raise ValueError("control graph statements/addresses length mismatch")
        nodes = tuple(ControlNode(i, address) for i, address in enumerate(addresses))
        known = {address for address in addresses if address is not None}
        if stmt_addr:
            known.update(address for address in stmt_addr.values() if address is not None)
        edges: list[ControlEdge] = []
        for source, statement in enumerate(statements):
            for kind, target in _address_targets(statement):
                edges.append(ControlEdge(source, target, kind))
        return cls(nodes, tuple(edges), frozenset(known))

    def validate_targets(self) -> None:
        """Reject an address that cannot be owned by the current statement graph."""

        for edge in self.edges:
            if edge.target not in self.addresses:
                raise ValueError(
                    f"jump target {edge.target:#x} is not a statement start"
                )

    @classmethod
    def from_events(cls, events: Iterable[Any]) -> "ControlGraph":
        """Build the graph from committed statement events.

        Addresses stay unresolved: an edge names the physical address the
        branch targets, not a statement index. A codeless event owns no
        address and so can never be a jump target.
        """
        events = tuple(events)
        nodes = tuple(
            ControlNode(event.seq, event.address) for event in events
        )
        # An arrival names an address precisely because it may own no
        # statement -- a procedure epilogue, an arm-close jmp. Letting one into
        # the address set would make `validate_targets` accept a target nothing
        # owns, which is the check's whole point.
        known = {
            e.address
            for e in events
            if e.address is not None and e.kind != "arrive"
        }
        # A revised statement is the one that matters: its first draft may
        # name a target the decoder went on to correct.
        from tbx.decode0.events import committed

        final = {e.seq: e.payload for e in committed(events)}
        edges: list[ControlEdge] = []
        for event in events:
            if event.kind in ("arrive", "patch"):
                continue  # a moment, or a revision already folded into `final`
            if event.kind == "branch":
                # A recognised branch names its target directly; there is no
                # committed statement to walk for an ("addr", n) operand. A
                # frame whose exit is not yet known contributes a node but no
                # edge -- inventing one would be a guessed target.
                if event.payload.target is not None:
                    edges.append(
                        ControlEdge(
                            event.seq, event.payload.target, event.payload.frame
                        )
                    )
                continue
            for kind, target in _address_targets(final.get(event.seq, event.payload)):
                edges.append(ControlEdge(event.seq, target, kind))
        return cls(nodes, tuple(edges), frozenset(known))

    def resolve(self, address: int | None) -> int | None:
        """The node owning ``address``, or None when no node does."""
        if address is None:
            return None
        for node in self.nodes:
            if node.address == address:
                return node.index
        return None

    def outgoing(self, source: int) -> tuple[ControlEdge, ...]:
        return tuple(edge for edge in self.edges if edge.source == source)


def _address_targets(value: Any) -> tuple[tuple[str, int], ...]:
    found: list[tuple[str, int]] = []

    def visit(item: Any, field_name: str = "branch") -> None:
        if isinstance(item, tuple) and len(item) == 2 and item[0] == "addr":
            if not isinstance(item[1], int):
                raise ValueError(f"non-integer control-flow target: {item!r}")
            found.append((field_name, item[1]))
            return
        if is_dataclass(item):
            for field in fields(item):
                visit(getattr(item, field.name), field.name)
        elif isinstance(item, (tuple, list)):
            for child in item:
                visit(child, field_name)

    visit(value)
    return tuple(found)


#: Calibrated branch template -> the construct it denotes.
#:
#: This table is the judgement the handlers used to make individually. An
#: inline IF and a head-tested loop are indistinguishable in the graph -- both
#: branch forward with no condition -- so the construct cannot be recovered
#: from shape. It follows from which template matched, and that is recorded.
FRAME_BY_TEMPLATE: dict[str, str] = {
    "inline_if_target": "if",
    "direct_flag_skip": "if",
    "bool_tail_skip": "if",
    "materialized_test_skip": "if",
    "bool_tail_loopback": "loop",
    "poll_loop": "loop",
    "for_header": "loop",
    "select_header": "case",
}


def frame_for(template: str) -> str:
    """The construct a calibrated branch template denotes.

    Fail-loud on an unmapped template: a new branch template must state what
    it means rather than defaulting to the commonest construct.
    """
    try:
        return FRAME_BY_TEMPLATE[template]
    except KeyError:
        raise ValueError(f"unmapped branch template: {template!r}") from None


@dataclass(frozen=True)
class BranchOutcome:
    """What became of one committed branch, and which pass decided it."""

    #: ``seq`` of the committing event.
    seq: int
    #: Physical address of the branch statement, if it owns one.
    address: int | None
    #: Physical address the branch targets.
    target: int
    #: What became of the branch. "raw" when it survives as a jump statement,
    #: "absorbed" when folding moved it inside another statement's body,
    #: "folded" when folding rewrote it, and "frame" when the handler opened a
    #: construct for it without ever committing a statement.
    outcome: str
    #: The pass responsible, from the statement edit log. None for a raw
    #: branch, which no pass touched.
    decided_by: str | None = None
    #: Whether the target is owned by a committed statement.
    resolvable: bool = True


def classify_branches(program) -> tuple[BranchOutcome, ...]:
    """Say what became of every committed branch in ``program``.

    The reconciliation says whether a branch survived, was absorbed into a
    body, or was rewritten. The edit log says which pass did it. Neither is
    inferred from the branch's shape -- that inference is exactly what this
    chapter is trying to remove from the expression handlers.
    """
    graph = ControlGraph.from_events(program.events)
    report = program.event_reconciliation
    absorbed = frozenset(report.absorbed if report else ())
    rewritten = frozenset(report.rewritten if report else ())

    frame_seqs = {e.seq for e in program.events if e.kind == "branch"}
    by_seq = {node.index: node for node in graph.nodes}
    outcomes = []
    for edge in graph.edges:
        if edge.source in frame_seqs:
            # A recognised frame: the handler decided the construct without
            # committing a statement, so no statement edit can account for it.
            outcome = "frame"
        elif edge.source in absorbed:
            outcome = "absorbed"
        elif edge.source in rewritten:
            outcome = "folded"
        else:
            outcome = "raw"
        outcomes.append(
            BranchOutcome(
                seq=edge.source,
                address=by_seq[edge.source].address,
                target=edge.target,
                outcome=outcome,
                decided_by=(
                    edge.kind
                    if outcome == "frame"
                    else _deciding_pass(program, edge.source)
                    if outcome != "raw"
                    else None
                ),
                resolvable=edge.target in graph.addresses,
            )
        )
    return tuple(outcomes)


def _deciding_pass(program, seq: int) -> str | None:
    """The pass whose edit removed the statement committed at ``seq``.

    Commits and transformations share one ordered log, so the first
    attributed edit after this statement's own commit is the pass that acted
    on it.
    """
    commits = 0
    for edit in program.statement_edits:
        if edit.kind == "append" and edit.origin is None:
            if commits == seq:
                pass
            commits += 1
        elif edit.origin is not None and commits > seq:
            return edit.origin
    return None


def predict_fold_starts(program) -> tuple[int, ...]:
    """Where each recorded inline-IF frame's fold region begins.

    The handlers locate this today with frame bookkeeping kept while decoding
    (`"idx": len(self.stmts)` when the frame opens). The same position is
    recoverable from the record: replay the statement edits that preceded the
    branch in the event stream, and the length of the resulting list is where
    its body starts.

    Replaying rather than counting commits is what makes it exact. A count of
    committed statements misses that an earlier fold already shortened the
    list, which is wrong for seven of the sixty-two programs in the corpus
    that fold an inline IF.
    """
    edits = tuple(program.statement_edits)
    starts = []
    for event in program.events:
        if event.kind != "branch" or event.payload.frame != "if":
            continue
        starts.append(_length_at(edits, event.seq))
    return tuple(starts)


def predict_fold_extents(program) -> tuple[tuple[int, int], ...]:
    """Where each recorded inline-IF frame's fold region begins and ends.

    The end is the harder half. A start can be counted, because it is a
    position in a list that exists; an end is a moment -- the list's length
    when decoding reaches the branch's target. Statement addresses cannot
    supply it: the target is often a procedure epilogue or an arm-close jmp,
    which own no statement, and when one does own it an earlier fold has
    already moved where it sits. From statement addresses alone this reaches
    26 of the 62 programs in the corpus that fold an inline IF.

    So the moment is recorded. An arrival event marks decoding reaching an
    address a branch wants, and the extent is the list length there, replayed
    from the edits stamped up to that event. A frame whose target is never
    arrived at yields nothing rather than a guessed end.

    Frames sharing an arrival are nested and all end at that one moment, so
    they all end at the same length. What the enclosing region ends up
    spanning once the inner ones have collapsed is the folding pass's own
    arithmetic -- it depends on the order the pass folds in, and on what else
    it has folded since. It is deliberately not applied here: this returns the
    regions the record describes, which is what the walk itself records.

    Returned in fold order: by arrival, and innermost first within one.
    """
    edits = tuple(program.statement_edits)
    arrivals: dict[int, int] = {}
    for event in program.events:
        if event.kind == "arrive":
            arrivals.setdefault(event.payload.address, event.seq)

    opened: dict[int, list[int]] = {}
    for event in program.events:
        if event.kind != "branch" or event.payload.frame != "if":
            continue
        arrival = arrivals.get(event.payload.target)
        if arrival is None or arrival < event.seq:
            continue  # never reached, or reached before the branch opened
        opened.setdefault(arrival, []).append(_length_at(edits, event.seq))

    regions = []
    for arrival in sorted(opened):
        stop = _length_at(edits, arrival)
        for start in reversed(opened[arrival]):
            regions.append((start, stop))
    return tuple(regions)


def _position_now(edits, seq: int, index: int) -> int:
    """Where a boundary recorded at ``index`` at event ``seq`` has moved to.

    `_length_at` answers a question about the past: how long the list was when
    a branch was recognised. Using that number as an index into the list as it
    stands now is only right while nothing has been inserted BELOW it since --
    and a codeless loop header is exactly such an insertion. Splicing a `DO`
    ahead of the loop body moves every statement after it down one, so the
    remembered length then names the statement before the body rather than its
    first, and the region takes in a statement that precedes the branch's own
    address (wild cal.exe: the IF at 0x14c72 collecting the INPUT at 0x14c61).

    Only edits strictly below the boundary move it. An insert AT the boundary
    puts the new statement at the region's first position, which is where a
    header shared with the body belongs and what the fold already expects
    (t1_dogotobody); shifting for it would push the body start past a
    statement that is genuinely inside.
    """
    from bisect import bisect_right

    if not isinstance(edits, (list, tuple)):
        edits = list(edits)
    for edit in edits[bisect_right(edits, seq, key=lambda e: e.at_event):]:
        if edit.index is None:
            continue
        if edit.kind == "insert" and edit.index < index:
            index += 1
        elif edit.kind == "delete" and edit.index < index:
            index -= 1
        elif edit.kind == "splice" and edit.stop is not None and edit.stop <= index:
            index += len(edit.payload) - (edit.stop - edit.index)
    return index


def _length_at(edits, seq: int) -> int:
    """The statement list's length at event ``seq``.

    Replaying rather than counting commits is what makes it exact: a count of
    committed statements misses that an earlier fold already shortened the
    list.

    The walk stamps edits with a clock that only advances, so the edits up to
    an event are a prefix -- found by bisection rather than by filtering the
    whole log, which keeps this cheap enough to run inside the fold.
    """
    from bisect import bisect_right

    from tbx.decode0.statement_log import replay

    if not isinstance(edits, (list, tuple)):
        edits = list(edits)  # the fold hands its own list; do not copy it
    return len(replay(edits[: bisect_right(edits, seq, key=lambda e: e.at_event)]))
