"""Address-level control-flow graph used by the lifting boundary.

This is an intentionally conservative first extraction. It records every
address-bearing branch in structured IR and validates that the target is known
before the legacy body-line resolver converts addresses to statement indices.
The existing resolver remains authoritative for nested SUB/IF physical-line
mapping; this graph makes its input and failure evidence explicit first.
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
