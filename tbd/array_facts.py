"""Computed array references translated from calibrated compiler templates."""

from __future__ import annotations

from collections.abc import Iterable

from tbd.compiler_ops import CompilerOp, translate_operations
from tbd.facts import Evidence, NamedPass
from tbd.ir import Fact
from tbd.semantic import combine_evidence, resolve_expression

_INDEX_LOADS = {
    "fild": "integer",
    "fild32": "long",
    "fld": "float",
    "fld64": "double",
}
_NUMERIC_STORES = {
    "fistp_si": "integer",
    "fistp_si32": "long",
    "fstp_si": "float",
    "fstp_si64": "double",
    "far_fistp_si": "integer",
    "far_fistp_si32": "long",
    "far_fstp_si": "float",
    "far_fstp_si64": "double",
    "far_fistp": "integer",
    "far_fistp32": "long",
    "far_fstp": "float",
    "far_fstp64": "double",
}


def array_store_facts(
    evidence: Evidence, facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Name complete computed-element stores independently of their producer."""

    operations = translate_operations(evidence.instructions)
    for index in range(len(operations)):
        match = _numeric_indexed_store(operations, index, facts)
        if match is None:
            match = _string_indexed_store(operations, index, facts)
        if match is None:
            match = _direct_dynamic_store(operations, index, facts)
        if match is not None:
            yield match


def _numeric_indexed_store(
    operations: tuple[CompilerOp, ...], index: int, facts: frozenset[Fact]
) -> Fact | None:
    if index + 6 >= len(operations):
        return None
    load, convert, sync, reload, transfer = operations[index : index + 5]
    source_kind = _INDEX_LOADS.get(load.kind)
    if (
        source_kind is None
        or len(load.args) != 1
        or not isinstance(load.args[0], int)
        or (convert.kind, convert.args) != ("fistp", (0x2C,))
        or sync.kind != "fwait"
        or (reload.kind, reload.args) != ("movaxmem", (0x2C,))
        or transfer.kind != "movsiax"
    ):
        return None
    cursor = index + 5
    while cursor < len(operations) and operations[cursor].kind == "shlsi":
        cursor += 1
    shifts = cursor - (index + 5)
    if shifts == 0 or cursor + 1 >= len(operations):
        return None
    anchor, terminal = operations[cursor : cursor + 2]
    target_kind = _NUMERIC_STORES.get(terminal.kind)
    if target_kind is None or not _contiguous(operations[index : cursor + 2]):
        return None
    layout = _indexed_layout(anchor, terminal, target_kind, shifts, facts)
    if layout is None:
        return None
    name, layout_evidence = layout
    resolved = resolve_expression(("memory", load.args[0], source_kind), facts)
    if resolved is None:
        return None
    return _store_fact(
        load,
        terminal,
        name,
        resolved.value,
        target_kind,
        combine_evidence(
            tuple(item.offset for item in operations[index : cursor + 2]),
            resolved.evidence,
            layout_evidence,
        ),
    )


def _string_indexed_store(
    operations: tuple[CompilerOp, ...], index: int, facts: frozenset[Fact]
) -> Fact | None:
    load = operations[index]
    if load.kind != "movsim" or len(load.args) != 1 or not isinstance(load.args[0], int):
        return None
    cursor = index + 1
    while cursor < len(operations) and operations[cursor].kind == "shlsi":
        cursor += 1
    shifts = cursor - index - 1
    if shifts == 0 or cursor + 1 >= len(operations):
        return None
    anchor, terminal = operations[cursor : cursor + 2]
    if (
        anchor.kind != "addsi"
        or terminal.kind != "strassign"
        or not _contiguous(operations[index : cursor + 2])
    ):
        return None
    layout = _static_layout(anchor, "string", shifts, facts)
    resolved = resolve_expression(("memory", load.args[0], "integer"), facts)
    if layout is None or resolved is None:
        return None
    name, layout_evidence = layout
    return _store_fact(
        load,
        terminal,
        name,
        resolved.value,
        "string",
        combine_evidence(
            tuple(item.offset for item in operations[index : cursor + 2]),
            resolved.evidence,
            layout_evidence,
        ),
    )


def _direct_dynamic_store(
    operations: tuple[CompilerOp, ...], index: int, facts: frozenset[Fact]
) -> Fact | None:
    if index + 1 >= len(operations):
        return None
    anchor, terminal = operations[index : index + 2]
    target_kind = _NUMERIC_STORES.get(terminal.kind)
    if (
        anchor.kind != "moves_m"
        or target_kind is None
        or not terminal.kind.startswith("far_")
        or len(anchor.args) != 1
        or len(terminal.args) != 1
        or not all(isinstance(value, int) for value in anchor.args + terminal.args)
        or anchor.end != terminal.offset
    ):
        return None
    runtime = _runtime_layout(anchor.args[0], target_kind, facts)
    if runtime is None:
        return None
    name, width, layout_evidence = runtime
    displacement = terminal.args[0]
    if displacement < 0 or displacement % width:
        return None
    low = _runtime_low(name, facts)
    if low is None:
        return None
    return _store_fact(
        anchor,
        terminal,
        name,
        ("const", low + displacement // width),
        target_kind,
        combine_evidence((anchor.offset, terminal.offset), layout_evidence),
    )


def _indexed_layout(
    anchor: CompilerOp,
    terminal: CompilerOp,
    kind: str,
    shifts: int,
    facts: frozenset[Fact],
) -> tuple[str, tuple[int, ...]] | None:
    if anchor.kind == "addsi" and not terminal.kind.startswith("far_"):
        return _static_layout(anchor, kind, shifts, facts)
    if anchor.kind != "moves_m" or not terminal.kind.startswith("far_"):
        return None
    runtime = _runtime_layout(anchor.args[0], kind, facts) if anchor.args else None
    if runtime is None:
        return None
    name, width, support = runtime
    return (name, support) if 1 << shifts == width else None


def _static_layout(
    anchor: CompilerOp, kind: str, shifts: int, facts: frozenset[Fact]
) -> tuple[str, tuple[int, ...]] | None:
    if len(anchor.args) != 1 or not isinstance(anchor.args[0], int):
        return None
    matches = [
        fact
        for fact in facts
        if fact.kind == "layout.array"
        and len(fact.value) == 7
        and fact.value[3] == kind
        and fact.value[4] == anchor.args[0]
        and fact.value[5] == 1 << shifts
        and isinstance(fact.value[1], str)
        and isinstance(fact.value[2], tuple)
        and len(fact.value[2]) == 1
    ]
    if len(matches) != 1:
        return None
    return matches[0].value[1], matches[0].evidence


def _runtime_layout(
    block: object, kind: str, facts: frozenset[Fact]
) -> tuple[str, int, tuple[int, ...]] | None:
    if not isinstance(block, int):
        return None
    matches = [
        fact
        for fact in facts
        if fact.kind == "layout.runtime_array"
        and fact.subject == ("runtime", block)
        and len(fact.value) == 6
        and fact.value[2] == kind
        and isinstance(fact.value[1], str)
        and fact.value[3] == 1
        and isinstance(fact.value[4], int)
    ]
    if len(matches) != 1:
        return None
    match = matches[0]
    return match.value[1], match.value[4], match.evidence


def _runtime_low(name: str, facts: frozenset[Fact]) -> int | None:
    for fact in facts:
        if fact.kind != "semantic.dynamic_dim" or fact.value[:1] != (name,):
            continue
        bounds = fact.value[1]
        if not isinstance(bounds, tuple) or len(bounds) != 1:
            continue
        bound = bounds[0]
        if (
            isinstance(bound, tuple)
            and len(bound) == 2
            and isinstance(bound[0], tuple)
            and bound[0][:1] == ("const",)
            and isinstance(bound[0][1], int)
        ):
            return bound[0][1]
        bases = [item.value[0] for item in facts if item.kind == "option.base"]
        return bases[0] if len(set(bases)) == 1 else 0
    return None


def _store_fact(
    start: CompilerOp,
    terminal: CompilerOp,
    name: str,
    index: object,
    kind: str,
    support: tuple[int, ...],
) -> Fact:
    return Fact(
        "reference.array_store",
        (start.offset, terminal.end),
        (("array", name, (index,)), kind),
        support,
        "anchored",
    )


def _contiguous(operations: tuple[CompilerOp, ...]) -> bool:
    return all(left.end == right.offset for left, right in zip(operations, operations[1:]))


ARRAY_REFERENCE_PASSES: tuple[NamedPass, ...] = (
    ("array-references", array_store_facts),
)
