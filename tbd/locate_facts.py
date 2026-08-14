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
