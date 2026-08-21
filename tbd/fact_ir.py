"""Build semantic operation IR directly from stable facts."""

from __future__ import annotations

from tbd.facts import Evidence
from tbd.ir import Fact, Operation

_OPERATION_KINDS = {
    "semantic.assign": "ir.assign",
    "semantic.out": "ir.out",
    "semantic.wait": "ir.wait",
    "semantic.lprint": "ir.lprint",
    "semantic.write": "ir.write",
    "semantic.lset": "ir.lset",
    "semantic.rset": "ir.rset",
    "semantic.field": "ir.field",
    "semantic.mid_assign": "ir.mid_assign",
    "semantic.swap": "ir.swap",
    "semantic.locate": "ir.locate",
    "semantic.read": "ir.read",
    "semantic.input_file": "ir.input_file",
    "semantic.input": "ir.input",
    "semantic.open": "ir.open",
    "semantic.close": "ir.close",
    "semantic.color": "ir.color",
    "semantic.screen": "ir.screen",
    "semantic.files": "ir.files",
    "semantic.for": "ir.for",
    "semantic.next": "ir.next",
    "semantic.do": "ir.do",
    "semantic.do_codeless": "ir.do",
    "semantic.loop": "ir.loop",
    "semantic.trap_ctl": "ir.trap_ctl",
    "semantic.on_trap": "ir.on_trap",
    "semantic.on_goto": "ir.on_goto",
    "semantic.on_gosub": "ir.on_gosub",
    "semantic.print": "ir.print",
    "semantic.if_goto": "ir.if_goto",
    "semantic.inline": "ir.inline",
    "semantic.delay": "ir.delay",
    "semantic.defseg": "ir.defseg",
    "semantic.dim": "ir.dim",
    "semantic.local_dim": "ir.dim",
    "semantic.common": "ir.common",
    "semantic.option_base": "ir.option_base",
    "semantic.dynamic_dim": "ir.dynamic_dim",
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
        if kind in {"ir.dim", "ir.common", "ir.option_base"}:
            operation = _static_dim_operation(evidence, fact)
            if operation is not None:
                operations.append(operation)
            continue
        if fact.kind == "semantic.do_codeless":
            operation = _codeless_operation(fact)
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
    if len(fact.subject) != 2:
        return None
    start, order = fact.subject
    if not isinstance(start, int) or not isinstance(order, int):
        return None
    raw = " ".join(
        evidence.image[address : address + 1].hex()
        for address in fact.evidence
        if 0 <= address < len(evidence.image)
    )
    operands = (order, *fact.value)
    return Operation(
        start,
        0,
        _OPERATION_KINDS[fact.kind],
        operands,
        raw,
        fact.confidence,
    )


def _codeless_operation(fact: Fact) -> Operation | None:
    if len(fact.subject) != 1 or not isinstance(fact.subject[0], int):
        return None
    return Operation(
        fact.subject[0],
        0,
        _OPERATION_KINDS[fact.kind],
        fact.value,
        "",
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
    if operation.kind in {"ir.dim", "ir.common", "ir.option_base"}:
        return operation.offset, operation.end, operation.operands[0], ""
    toggles = {"ir.tron": 0, "ir.troff": 1}
    if operation.kind == "ir.do":
        return operation.offset, operation.end, -1, operation.kind
    return operation.offset, operation.end, toggles.get(operation.kind, 1000), operation.kind
