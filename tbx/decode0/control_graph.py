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
        known = {e.address for e in events if e.address is not None}
        edges: list[ControlEdge] = []
        for event in events:
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
            for kind, target in _address_targets(event.payload):
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
