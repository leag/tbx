"""Computed array references translated from calibrated compiler templates."""

from __future__ import annotations

from collections.abc import Iterable

from tbd.compiler_ops import CompilerOp, translate_operations
from tbd.facts import Evidence, NamedPass
from tbd.ir import Fact
from tbd.semantic import Resolved, combine_evidence, resolve_expression

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
        match = _rank2_indexed_store(operations, index, facts)
        if match is None:
            match = _numeric_indexed_store(operations, index, facts)
        if match is None:
            match = _string_indexed_store(operations, index, facts)
        if match is None:
            match = _direct_dynamic_store(operations, index, facts)
        if match is not None:
            yield match


def array_read_facts(
    evidence: Evidence, facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Name complete rank-1 INTEGER element reads used as AX operands."""

    operations = translate_operations(evidence.instructions)
    for index, load in enumerate(operations):
        runtime = _runtime_array_read(operations, index, facts)
        if runtime is not None:
            yield runtime
        if load.kind != "movsim" or len(load.args) != 1:
            continue
        resolved = resolve_expression(
            ("memory", load.args[0], "integer"), facts
        )
        if resolved is None:
            continue
        cursor = index + 1
        while cursor < len(operations) and operations[cursor].kind == "shlsi":
            cursor += 1
        shifts = cursor - index - 1
        if shifts == 0 or cursor >= len(operations):
            continue
        anchor = operations[cursor]
        cursor += 1
        staged = cursor < len(operations) and operations[cursor].kind == "movbxax"
        if staged:
            cursor += 1
        if cursor >= len(operations) or operations[cursor].kind != "movax_si":
            continue
        terminal = operations[cursor]
        if not _contiguous(operations[index : cursor + 1]):
            continue
        layout = _static_layout(anchor, "integer", shifts, facts)
        if layout is None:
            continue
        name, layout_evidence = layout
        yield Fact(
            "reference.array_read",
            (load.offset, terminal.end),
            (("array", name, (resolved.value,)), "integer", staged),
            combine_evidence(
                tuple(item.offset for item in operations[index : cursor + 1]),
                resolved.evidence,
                layout_evidence,
            ),
            "anchored",
        )


def array_address_facts(
    evidence: Evidence, facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Resolve complete static rank-1 element-address calculations."""

    operations = translate_operations(evidence.instructions)
    for index in range(len(operations)):
        matched = _static_array_address(operations, index, facts)
        if matched is not None:
            yield matched


def _static_array_address(
    operations: tuple[CompilerOp, ...], index: int, facts: frozenset[Fact]
) -> Fact | None:
    operand = _integer_operand(operations, index, facts)
    if operand is None:
        return None
    start, resolved, cursor = operand
    before = cursor < len(operations) and operations[cursor].kind == "movbxsi"
    if before:
        cursor += 1
    if cursor >= len(operations) or operations[cursor].kind != "movsiax":
        return None
    cursor += 1
    after = cursor < len(operations) and operations[cursor].kind == "movaxbx"
    if after:
        cursor += 1
    if before != after:
        return None
    shift_start = cursor
    while cursor < len(operations) and operations[cursor].kind == "shlsi":
        cursor += 1
    shifts = cursor - shift_start
    if shifts == 0 or cursor >= len(operations):
        return None
    anchor = operations[cursor]
    if anchor.kind != "addsi" or not _contiguous(operations[index : cursor + 1]):
        return None
    layout = _static_address_layout(anchor, shifts, facts)
    if layout is None:
        return None
    name, kind, width, layout_evidence = layout
    return Fact(
        "reference.array_address",
        (start.offset, anchor.end),
        (("array", name, (resolved.value,)), kind, width, before),
        combine_evidence(
            tuple(item.offset for item in operations[index : cursor + 1]),
            resolved.evidence,
            layout_evidence,
        ),
        "anchored",
    )


def _static_address_layout(
    anchor: CompilerOp, shifts: int, facts: frozenset[Fact]
) -> tuple[str, str, int, tuple[int, ...]] | None:
    if len(anchor.args) != 1 or not isinstance(anchor.args[0], int):
        return None
    matches = [
        fact
        for fact in facts
        if fact.kind == "layout.array"
        and len(fact.value) == 7
        and isinstance(fact.value[1], str)
        and isinstance(fact.value[2], tuple)
        and len(fact.value[2]) == 1
        and isinstance(fact.value[3], str)
        and fact.value[4] == anchor.args[0]
        and fact.value[5] == 1 << shifts
    ]
    if len(matches) != 1:
        return None
    match = matches[0]
    return match.value[1], match.value[3], match.value[5], match.evidence


def _runtime_array_read(
    operations: tuple[CompilerOp, ...], index: int, facts: frozenset[Fact]
) -> Fact | None:
    if index + 6 >= len(operations):
        return None
    load = operations[index]
    if load.kind != "movax_m" or len(load.args) != 1:
        return None
    resolved = resolve_expression(
        ("memory", load.args[0], "integer"), facts
    )
    if resolved is None:
        return None
    cursor = index + 1
    normalize = operations[cursor]
    if normalize.kind != "subax_m" or len(normalize.args) != 1:
        return None
    cursor += 1
    if operations[cursor].kind != "movsiax":
        return None
    cursor += 1
    if cursor < len(operations) and operations[cursor].kind == "movaxbx":
        cursor += 1
    shift_start = cursor
    while cursor < len(operations) and operations[cursor].kind == "shlsi":
        cursor += 1
    shifts = cursor - shift_start
    if shifts == 0 or cursor >= len(operations):
        return None
    anchor = operations[cursor]
    if anchor.kind != "moves_m" or len(anchor.args) != 1:
        return None
    cursor += 1
    staged = cursor < len(operations) and operations[cursor].kind == "movbxax"
    if staged:
        cursor += 1
    if cursor >= len(operations) or operations[cursor].kind != "far_movax_si":
        return None
    cursor += 1
    trailing = cursor < len(operations) and operations[cursor].kind == "movbxax"
    if trailing:
        cursor += 1
    if not _contiguous(operations[index:cursor]):
        return None
    layout = _runtime_read_layout(
        anchor.args[0], normalize.args[0], shifts, facts
    )
    if layout is None:
        return None
    name, layout_evidence = layout
    end = operations[cursor - 1].end
    return Fact(
        "reference.array_read",
        (load.offset, end),
        (("array", name, (resolved.value,)), "integer", staged),
        combine_evidence(
            tuple(item.offset for item in operations[index:cursor]),
            resolved.evidence,
            layout_evidence,
        ),
        "anchored",
    )


def _runtime_read_layout(
    block: object,
    lower_bound: object,
    shifts: int,
    facts: frozenset[Fact],
) -> tuple[str, tuple[int, ...]] | None:
    if not isinstance(block, int) or lower_bound != block + 8:
        return None
    matches = [
        fact
        for fact in facts
        if fact.kind == "layout.runtime_array"
        and fact.subject == ("runtime", block)
        and len(fact.value) == 6
        and isinstance(fact.value[1], str)
        and fact.value[2] == "integer"
        and fact.value[3] == 1
        and fact.value[4] == 1 << shifts
    ]
    if len(matches) != 1:
        return None
    return matches[0].value[1], matches[0].evidence


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
    target_kind = _store_kind(terminal.kind)
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
        (resolved.value,),
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
    if shifts == 0 or cursor >= len(operations):
        return None
    anchor = operations[cursor]
    terminal_match = _indexed_terminal(operations, cursor + 1)
    if anchor.kind != "addsi" or terminal_match is None:
        return None
    terminal, target_kind, stop = terminal_match
    if not _contiguous(operations[index:stop]):
        return None
    layout = _static_layout(anchor, target_kind, shifts, facts)
    resolved = resolve_expression(("memory", load.args[0], "integer"), facts)
    if layout is None or resolved is None:
        return None
    name, layout_evidence = layout
    return _store_fact(
        load,
        terminal,
        name,
        (resolved.value,),
        target_kind,
        combine_evidence(
            tuple(item.offset for item in operations[index:stop]),
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
        (("const", low + displacement // width),),
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
    indices: tuple[object, ...],
    kind: str,
    support: tuple[int, ...],
) -> Fact:
    return Fact(
        "reference.array_store",
        (start.offset, terminal.end),
        (("array", name, indices), kind),
        support,
        "anchored",
    )


def _rank2_indexed_store(
    operations: tuple[CompilerOp, ...], index: int, facts: frozenset[Fact]
) -> Fact | None:
    if index + 7 > len(operations):
        return None
    first_match = _integer_operand(operations, index, facts)
    if first_match is None:
        return None
    first, left, cursor = first_match
    if cursor + 2 >= len(operations):
        return None
    span, stage = operations[cursor : cursor + 2]
    if (
        span.kind != "imul_m"
        or len(span.args) != 1
        or not isinstance(span.args[0], int)
        or stage.kind != "movsiax"
    ):
        return None
    second_match = _integer_operand(operations, cursor + 2, facts)
    if second_match is None:
        return None
    _second, right, cursor = second_match
    if cursor >= len(operations) or operations[cursor].kind != "addsiax":
        return None
    cursor += 1
    shift_start = cursor
    while cursor < len(operations) and operations[cursor].kind == "shlsi":
        cursor += 1
    shifts = cursor - shift_start
    if shifts == 0 or cursor >= len(operations):
        return None
    anchor = operations[cursor]
    terminal_match = _indexed_terminal(operations, cursor + 1)
    if terminal_match is None:
        return None
    terminal, target_kind, stop = terminal_match
    if not _contiguous(operations[index:stop]):
        return None
    layout = _rank2_layout(
        span.args[0], anchor, target_kind, shifts, facts
    )
    if layout is None:
        return None
    name, layout_evidence = layout
    return _store_fact(
        first,
        terminal,
        name,
        (right.value, left.value),
        target_kind,
        combine_evidence(
            tuple(item.offset for item in operations[index:stop]),
            left.evidence,
            right.evidence,
            layout_evidence,
        ),
    )


def _indexed_terminal(
    operations: tuple[CompilerOp, ...], index: int
) -> tuple[CompilerOp, str, int] | None:
    if index >= len(operations):
        return None
    direct = operations[index]
    kind = _store_kind(direct.kind)
    if kind is not None:
        return direct, kind, index + 1
    bridge = operations[index : index + 4]
    if (
        len(bridge) == 4
        and (bridge[0].kind, bridge[0].args) == ("fistp", (0x2C,))
        and bridge[1].kind == "fwait"
        and (bridge[2].kind, bridge[2].args) == ("movaxmem", (0x2C,))
        and bridge[3].kind in {"movm_ax_si", "far_movm_ax_si"}
    ):
        return bridge[3], "integer", index + 4
    return None


def _rank2_layout(
    span: int,
    anchor: CompilerOp,
    kind: str,
    shifts: int,
    facts: frozenset[Fact],
) -> tuple[str, tuple[int, ...]] | None:
    matches = []
    for fact in facts:
        if fact.kind == "layout.array" and len(fact.value) == 7:
            block = fact.subject[1] if len(fact.subject) == 2 else None
            valid_anchor = anchor.kind == "addsi" and anchor.args == (fact.value[4],)
            rank = len(fact.value[2]) if isinstance(fact.value[2], tuple) else 0
            fact_kind = fact.value[3]
            width = fact.value[5]
        elif fact.kind == "layout.runtime_array" and len(fact.value) == 6:
            block = fact.subject[1] if len(fact.subject) == 2 else None
            valid_anchor = anchor.kind == "moves_m" and anchor.args == (block,)
            fact_kind = fact.value[2]
            rank, width = fact.value[3:5]
        else:
            continue
        if (
            isinstance(block, int)
            and span == block + 0x0C
            and valid_anchor
            and isinstance(fact.value[1], str)
            and fact_kind == kind
            and rank == 2
            and width == 1 << shifts
        ):
            matches.append(fact)
    if len(matches) != 1:
        return None
    return matches[0].value[1], matches[0].evidence


def _integer_value(
    operation: CompilerOp, facts: frozenset[Fact]
) -> Resolved | None:
    if operation.kind == "movax" and len(operation.args) == 1:
        return resolve_expression(("const", operation.args[0]), facts)
    if (
        operation.kind == "movax_m"
        and len(operation.args) == 1
        and isinstance(operation.args[0], int)
    ):
        return resolve_expression(("memory", operation.args[0], "integer"), facts)
    return None


def _integer_operand(
    operations: tuple[CompilerOp, ...], index: int, facts: frozenset[Fact]
) -> tuple[CompilerOp, Resolved, int] | None:
    if index >= len(operations):
        return None
    first = operations[index]
    direct = _integer_value(first, facts)
    if direct is not None:
        return first, direct, index + 1
    bridge = operations[index : index + 4]
    source_kind = _INDEX_LOADS.get(first.kind)
    if (
        len(bridge) == 4
        and source_kind is not None
        and len(first.args) == 1
        and isinstance(first.args[0], int)
        and (bridge[1].kind, bridge[1].args) == ("fistp", (0x2C,))
        and bridge[2].kind == "fwait"
        and (bridge[3].kind, bridge[3].args) == ("movaxmem", (0x2C,))
    ):
        resolved = resolve_expression(
            ("memory", first.args[0], source_kind), facts
        )
        if resolved is not None:
            return first, resolved, index + 4
    return None


def _store_kind(kind: str) -> str | None:
    if kind in {"strassign", "far_strassign"}:
        return "string"
    return _NUMERIC_STORES.get(kind)


def _contiguous(operations: tuple[CompilerOp, ...]) -> bool:
    return all(left.end == right.offset for left, right in zip(operations, operations[1:]))


ARRAY_REFERENCE_PASSES: tuple[NamedPass, ...] = (
    ("array-references", array_store_facts),
    ("array-addresses", array_address_facts),
    ("array-reads", array_read_facts),
)
