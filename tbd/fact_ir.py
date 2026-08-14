"""Build semantic operation IR directly from stable facts."""

from __future__ import annotations

from tbd.facts import Evidence
from tbd.ir import Fact, Operation

_OPERATION_KINDS = {
    "semantic.assign": "ir.assign",
    "semantic.print": "ir.print",
    "semantic.if_goto": "ir.if_goto",
    "semantic.delay": "ir.delay",
    "semantic.defseg": "ir.defseg",
    "semantic.dim": "ir.dim",
    "semantic.gosub": "ir.gosub",
    "semantic.return": "ir.return",
    "semantic.resume": "ir.resume",
    "semantic.run": "ir.run",
    "semantic.call": "ir.call",
    "semantic.sub_def": "ir.sub_def",
    "semantic.tron": "ir.tron",
    "semantic.troff": "ir.troff",
    "semantic.statement": "tb.statement",
}


def build_operations(
    evidence: Evidence, facts: tuple[Fact, ...]
) -> tuple[Operation, ...]:
    """Materialize supported semantic facts without consulting legacy rewrites."""

    operations = []
    materialized: set[tuple[object, ...]] = set()
    for fact in facts:
        kind = _OPERATION_KINDS.get(fact.kind)
        identity = fact.kind, fact.subject, fact.value
        if kind is None or identity in materialized:
            continue
        materialized.add(identity)
        if kind == "ir.dim":
            operation = _static_dim_operation(evidence, fact)
            if operation is not None:
                operations.append(operation)
            continue
        span = _span(fact, len(evidence.image))
        if span is None:
            continue
        start, end = span
        raw = evidence.image[start:end].hex(" ")
        operations.append(
            Operation(start, end - start, kind, fact.value, raw, fact.confidence)
        )
    return tuple(sorted(operations, key=_operation_key))


def _static_dim_operation(
    evidence: Evidence, fact: Fact
) -> Operation | None:
    if len(fact.subject) != 2 or len(fact.value) != 4:
        return None
    start, order = fact.subject
    if not isinstance(start, int) or not isinstance(order, int):
        return None
    raw = " ".join(
        evidence.image[address : address + 1].hex()
        for address in fact.evidence
        if 0 <= address < len(evidence.image)
    )
    return Operation(
        start,
        0,
        "ir.dim",
        (order, *fact.value),
        raw,
        fact.confidence,
    )


def _span(fact: Fact, image_size: int) -> tuple[int, int] | None:
    if len(fact.subject) != 2:
        return None
    start, end = fact.subject
    if not isinstance(start, int) or not isinstance(end, int):
        return None
    return (start, end) if 0 <= start < end <= image_size else None


def _operation_key(operation: Operation) -> tuple[int, int, int, str]:
    if operation.kind == "ir.dim":
        return operation.offset, operation.end, operation.operands[0], ""
    toggles = {"ir.tron": 0, "ir.troff": 1}
    return operation.offset, operation.end, toggles.get(operation.kind, 1000), operation.kind
