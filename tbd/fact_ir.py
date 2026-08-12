"""Build semantic operation IR directly from stable facts."""

from __future__ import annotations

from tbd.facts import Evidence
from tbd.ir import Fact, Operation

_OPERATION_KINDS = {
    "semantic.assign": "ir.assign",
    "semantic.print": "ir.print",
    "semantic.if_goto": "ir.if_goto",
    "semantic.delay": "ir.delay",
    "semantic.statement": "tb.statement",
}


def build_operations(
    evidence: Evidence, facts: tuple[Fact, ...]
) -> tuple[Operation, ...]:
    """Materialize supported semantic facts without consulting legacy rewrites."""

    operations = []
    for fact in facts:
        kind = _OPERATION_KINDS.get(fact.kind)
        span = _span(fact, len(evidence.image))
        if kind is None or span is None:
            continue
        start, end = span
        raw = evidence.image[start:end].hex(" ")
        operations.append(
            Operation(start, end - start, kind, fact.value, raw, fact.confidence)
        )
    return tuple(sorted(operations, key=_operation_key))


def _span(fact: Fact, image_size: int) -> tuple[int, int] | None:
    if len(fact.subject) != 2:
        return None
    start, end = fact.subject
    if not isinstance(start, int) or not isinstance(end, int):
        return None
    return (start, end) if 0 <= start < end <= image_size else None


def _operation_key(operation: Operation) -> tuple[int, int, str]:
    return operation.offset, operation.end, operation.kind
