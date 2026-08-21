"""LOCATE facts over complete grouped runtime-call legs."""

from __future__ import annotations

import struct
from collections.abc import Iterable
from dataclasses import dataclass

from tbd.facts import Evidence, NamedPass
from tbd.ir import Fact, Operation
from tbd.semantic import combine_evidence, resolve_expression


@dataclass(frozen=True)
class _Leg:
    size: int
    position: int
    values: tuple[object, ...]
    evidence: tuple[int, ...]


def locate_statement_facts(
    evidence: Evidence, facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Resolve whole LOCATE statements without emitting partial call legs."""

    instructions = evidence.instructions
    index = 0
    while index < len(instructions):
        expression = _string_length_row_col(
            instructions[index : index + 8], facts
        )
        if expression is not None:
            yield expression
            index += 8
            continue
        row_col = _row_col(instructions[index : index + 4])
        cursor = None
        shape = None
        if row_col is not None:
            cursor = _cursor(instructions[index + row_col.size : index + row_col.size + 2])
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
    string = resolve_expression(
        ("memory", setup.operands[1], "string"), facts
    )
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
    values = [None, None, None, None, None]
    for leg in legs:
        values[leg.position : leg.position + len(leg.values)] = leg.values
    if values[0] == ("const", 0x8000):
        values[0] = None
    resolved = []
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
    if index >= len(instructions):
        return False
    following = instructions[index]
    return (
        following.kind in {"tb.statement", "tb.epilogue"}
        or _row_col(instructions[index : index + 4]) is not None
        or _ax_value(following) is None
    )


def _runtime_vector(instruction: Operation) -> int | None:
    if instruction.kind != "tb.runtime" or not instruction.operands:
        return None
    value = instruction.operands[0]
    return value if isinstance(value, int) else None


def _support(window: tuple[Operation, ...]) -> tuple[int, ...]:
    return tuple(instruction.offset for instruction in window)


def _contiguous(instructions: tuple[Operation, ...]) -> bool:
    return all(
        left.end == right.offset
        for left, right in zip(instructions, instructions[1:])
    )


LOCATE_FACT_PASSES: tuple[NamedPass, ...] = (("locate", locate_statement_facts),)
