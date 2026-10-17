from __future__ import annotations

import struct
from collections.abc import Iterable
from dataclasses import dataclass

from tbd.facts import Evidence, NamedPass, fact_key, reads
from tbd.ir import Fact, Operation
from tbd.matchers import direct_fp_source, fp_ax_bridge
from tbd.operation_helpers import contiguous as _contiguous
from tbd.semantic import combine_evidence, resolve_expression


@dataclass(frozen=True)
class _Leg:
    size: int
    position: int
    values: tuple[object, ...]
    evidence: tuple[int, ...]


@reads(
    "constant",
    "expression.system",
    "layout.array",
    "reference.array_read",
    "signature",
    "slot",
    "tb.epilogue",
    "tb.function",
    "tb.runtime",
    "tb.statement",
    "x86.mov_imm",
)
def locate_statement_facts(
    evidence: Evidence, facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Recover LOCATE statements and their row/column expressions."""
    instructions = evidence.instructions
    by_offset = {instruction.offset: instruction for instruction in instructions}
    reads = sorted(
        (
            fact
            for fact in facts
            if fact.kind == "reference.array_read"
            and len(fact.subject) == 2
            and len(fact.value) == 3
        ),
        key=lambda fact: (fact.subject, fact_key(fact)),
    )
    for row, column in zip(reads, reads[1:]):
        runtime = by_offset.get(column.subject[1])
        if (
            row.subject[1] != column.subject[0]
            or column.value[2] is not True
            or runtime is None
            or _runtime_vector(runtime) != 0xCF
        ):
            continue
        yield Fact(
            "semantic.locate",
            (row.subject[0], runtime.end),
            (row.value[0], column.value[0], None, None, None),
            combine_evidence(row.evidence, column.evidence, (runtime.offset,)),
            "anchored",
        )
    by_end = {instruction.end: instruction for instruction in instructions}
    for instruction in instructions:
        if _runtime_vector(instruction) == 0xCF:
            converted = _converted_row_col(instruction, by_end, facts)
            if converted is None:
                converted = _converted_row(instruction, by_end, facts)
            if converted is not None:
                yield converted
    index = 0
    while index < len(instructions):
        expression = _string_length_row_col(instructions[index : index + 8], facts)
        if expression is not None:
            yield expression
            index += 8
            continue
        row_col = _row_col(instructions[index : index + 4])
        cursor = None
        shape = None
        if row_col is not None:
            cursor = _cursor(
                instructions[index + row_col.size : index + row_col.size + 2]
            )
            used = row_col.size + (cursor.size if cursor else 0)
            shape = _shape(instructions[index + used : index + used + 4])
        else:
            cursor = _cursor(instructions[index : index + 2])
            used = cursor.size if cursor else 0
            shape = _shape(instructions[index + used : index + used + 4])
        if row_col is None and cursor is None and shape is None:
            index += 1
            continue
        legs = tuple(leg for leg in (row_col, cursor, shape) if leg is not None)
        consumed = sum(leg.size for leg in legs)
        end_index = index + consumed
        if shape is not None or _has_boundary(instructions, end_index):
            fact = _locate_fact(instructions, index, legs, facts)
            if fact is not None:
                yield fact
        index = end_index


def _converted_row_col(
    runtime: Operation, by_end: dict[int, Operation], facts: frozenset[Fact]
) -> Fact | None:
    """Recover ``LOCATE r, c`` whose column is converted from a real.

    A single-precision column reaches AX through the scratch word, and the
    compiler stages the row in BX inside that conversion:
    ``fld [c]; fistp [2Ch]; mov bx,ax; fwait; mov ax,[2Ch]``.  The row is the
    AX value before it, itself converted the same way or loaded directly.
    """
    reload = by_end.get(runtime.offset)
    wait = by_end.get(reload.offset) if reload is not None else None
    stage = by_end.get(wait.offset) if wait is not None else None
    store = by_end.get(stage.offset) if stage is not None else None
    load = by_end.get(store.offset) if store is not None else None
    if (
        reload is None
        or bytes.fromhex(reload.raw) != b"\xa1\x2c\x00"
        or wait is None
        or wait.kind != "tb.fwait"
        or stage is None
        or bytes.fromhex(stage.raw) != b"\x89\xc3"
        or store is None
        or bytes.fromhex(store.raw) != b"\xcd\x3b\x1e\x2c\x00"
    ):
        return None
    column_source = direct_fp_source(load)
    row_end = by_end.get(load.offset) if load is not None else None
    if column_source is None or row_end is None or load is None:
        return None
    bridge = fp_ax_bridge(row_end, by_end)
    if bridge is not None:
        row_source, row_evidence = bridge
    else:
        row_source = _ax_value(row_end)
        row_evidence = (row_end.offset,)
    if row_source is None:
        return None
    row = resolve_expression(row_source, facts)
    column = resolve_expression(column_source, facts)
    if row is None or column is None:
        return None
    return Fact(
        "semantic.locate",
        (min(row_evidence), runtime.end),
        (row.value, column.value, None, None, None),
        combine_evidence(
            row_evidence,
            row.evidence,
            column.evidence,
            (load.offset, store.offset, stage.offset, wait.offset, reload.offset),
            (runtime.offset,),
        ),
        "anchored",
    )


def _converted_row(
    runtime: Operation, by_end: dict[int, Operation], facts: frozenset[Fact]
) -> Fact | None:
    """Recover ``LOCATE r, c`` whose row is converted from a real.

    ``fld [r]; fistp [2Ch]; fwait; mov ax,[2Ch]; mov bx,ax; mov ax,c``: the
    row is staged in BX before the column is loaded.
    """
    column_end = by_end.get(runtime.offset)
    stage = by_end.get(column_end.offset) if column_end is not None else None
    row_end = by_end.get(stage.offset) if stage is not None else None
    column_source = _ax_value(column_end) if column_end is not None else None
    if (
        stage is None
        or bytes.fromhex(stage.raw) != b"\x89\xc3"
        or column_source is None
    ):
        return None
    bridge = fp_ax_bridge(row_end, by_end)
    if bridge is None:
        return None
    row_source, row_evidence = bridge
    row = resolve_expression(row_source, facts)
    column = resolve_expression(column_source, facts)
    if row is None or column is None:
        return None
    return Fact(
        "semantic.locate",
        (min(row_evidence), runtime.end),
        (row.value, column.value, None, None, None),
        combine_evidence(
            row_evidence,
            row.evidence,
            column.evidence,
            (stage.offset, column_end.offset, runtime.offset),
        ),
        "anchored",
    )


def _string_length_row_col(
    window: tuple[Operation, ...], facts: frozenset[Fact]
) -> Fact | None:
    if len(window) != 8 or not _contiguous(window):
        return None
    row, setup, push, stage, function, negate, add, runtime = window
    row_value = _ax_value(row)
    add_raw = bytes.fromhex(add.raw)
    if (
        row_value is None
        or setup.kind != "x86.mov_imm"
        or setup.operands[:1] != ("si",)
        or len(setup.operands) != 2
        or not isinstance(setup.operands[1], int)
        or _runtime_vector(push) != 0x9C
        or bytes.fromhex(stage.raw) != b"\x89\xc3"
        or function.kind != "tb.function"
        or function.operands != ("numeric", 0x22)
        or bytes.fromhex(negate.raw) != b"\xf7\xd8"
        or len(add_raw) != 4
        or add_raw[:2] != b"\x03\x06"
        or _runtime_vector(runtime) != 0xCF
    ):
        return None
    row_result = resolve_expression(row_value, facts)
    string = resolve_expression(("memory", setup.operands[1], "string"), facts)
    constant = resolve_expression(
        ("memory", struct.unpack_from("<H", add_raw, 2)[0], "integer"),
        facts,
    )
    if row_result is None or string is None or constant is None:
        return None
    length = "call", "LEN", (string.value,)
    column = "binary", "-", constant.value, length
    return Fact(
        "semantic.locate",
        (row.offset, runtime.end),
        (row_result.value, column, None, None, None),
        combine_evidence(
            tuple(item.offset for item in window),
            row_result.evidence,
            string.evidence,
            constant.evidence,
        ),
        "signature",
    )


def _locate_fact(
    instructions: tuple[Operation, ...],
    index: int,
    legs: tuple[_Leg, ...],
    facts: frozenset[Fact],
) -> Fact | None:
    values: list[object | None] = [None, None, None, None, None]
    for leg in legs:
        values[leg.position : leg.position + len(leg.values)] = leg.values
    if values[0] == ("const", 0x8000):
        values[0] = None
    resolved: list[object | None] = []
    support = [leg.evidence for leg in legs]
    for value in values:
        if value is None:
            resolved.append(None)
            continue
        item = resolve_expression(value, facts)
        if item is None:
            return None
        resolved.append(item.value)
        support.append(item.evidence)
    end = instructions[index + sum(leg.size for leg in legs) - 1].end
    return Fact(
        "semantic.locate",
        (instructions[index].offset, end),
        tuple(resolved),
        combine_evidence(*support),
        "signature",
    )


def _row_col(window: tuple[Operation, ...]) -> _Leg | None:
    if len(window) != 4 or not _contiguous(window):
        return None
    row, stage, col, runtime = window
    row_value = _ax_value(row)
    col_value = _ax_value(col)
    if (
        row_value is None
        or col_value is None
        or bytes.fromhex(stage.raw) != b"\x89\xc3"
        or _runtime_vector(runtime) != 0xCF
    ):
        return None
    return _Leg(4, 0, (row_value, col_value), _support(window))


def _cursor(window: tuple[Operation, ...]) -> _Leg | None:
    if len(window) != 2 or not _contiguous(window):
        return None
    value, runtime = window
    expression = _ax_value(value)
    if expression is None or _runtime_vector(runtime) != 0xD0:
        return None
    return _Leg(2, 2, (expression,), _support(window))


def _shape(window: tuple[Operation, ...]) -> _Leg | None:
    if len(window) != 4 or not _contiguous(window):
        return None
    start, stage, stop, runtime = window
    start_value = _ax_value(start)
    stop_value = _ax_value(stop)
    if (
        start_value is None
        or stop_value is None
        or bytes.fromhex(stage.raw) != b"\x89\xc3"
        or _runtime_vector(runtime) != 0xCE
    ):
        return None
    return _Leg(4, 3, (start_value, stop_value), _support(window))


def _ax_value(instruction: Operation) -> object | None:
    if (
        instruction.kind == "x86.mov_imm"
        and len(instruction.operands) == 2
        and instruction.operands[0] == "ax"
    ):
        return "const", instruction.operands[1]
    raw = bytes.fromhex(instruction.raw)
    if raw == b"\x31\xc0":
        return "const", 0
    if len(raw) == 4 and raw[:2] == b"\x8b\x06":
        return "memory", struct.unpack_from("<H", raw, 2)[0], "integer"
    return None


def _has_boundary(instructions: tuple[Operation, ...], index: int) -> bool:
    """Report whether the LOCATE ends here rather than continuing.

    A following AX load is held back because it may begin a cursor or shape
    leg of this same LOCATE.  When it begins neither, it belongs to the next
    statement and cannot extend this one.
    """
    if index >= len(instructions):
        return False
    following = instructions[index]
    if following.kind in {"tb.statement", "tb.epilogue"}:
        return True
    if _row_col(instructions[index : index + 4]) is not None:
        return True
    if _ax_value(following) is None:
        return True
    return (
        _cursor(instructions[index : index + 2]) is None
        and _shape(instructions[index : index + 4]) is None
    )


def _runtime_vector(instruction: Operation) -> int | None:
    if instruction.kind != "tb.runtime" or not instruction.operands:
        return None
    value = instruction.operands[0]
    return value if isinstance(value, int) else None


def _support(window: tuple[Operation, ...]) -> tuple[int, ...]:
    return tuple(instruction.offset for instruction in window)


LOCATE_FACT_PASSES: tuple[NamedPass, ...] = (("locate", locate_statement_facts),)
