from __future__ import annotations

import struct
from collections.abc import Iterable
from dataclasses import dataclass

from tbd.compiler_ops import CompilerOp, translate_operations
from tbd.facts import Evidence, NamedPass, reads
from tbd.input_facts import _array_stores_by_start, array_input_item, integer_input_item
from tbd.ir import Fact, Operation
from tbd.operation_helpers import runtime_vector as _runtime_vector
from tbd.operation_helpers import statement_name as _phase_name
from tbd.profile import FP_TRANSFER_TYPES
from tbd.semantic import (
    combine_evidence,
    resolve_array_element,
    resolve_expression,
    resolve_slot,
)


@dataclass(frozen=True)
class _Item:
    size: int
    reference: object
    kind: str
    evidence: tuple[int, ...]


@reads(
    "constant",
    "expression.system",
    "layout.array",
    "machine.store",
    "reference.array_store",
    "slot",
    "tb.fn_call",
    "tb.fn_return",
    "tb.fp",
    "tb.fp_far",
    "tb.fwait",
    "tb.runtime",
    "tb.statement",
    "x86.inc",
    "x86.j",
    "x86.jmp",
    "x86.mov_acc_mem",
    "x86.mov_imm",
)
def input_file_statement_facts(
    evidence: Evidence, facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Recover file-backed INPUT statements and destinations."""

    instructions = evidence.instructions
    compiler_ops = {
        operation.offset: operation for operation in translate_operations(instructions)
    }
    array_stores = _array_stores_by_start(facts)
    instruction_ends = {item.end: index for index, item in enumerate(instructions)}
    by_end = {instruction.end: instruction for instruction in instructions}
    index = 0
    while index < len(instructions):
        first = _item(
            instructions, index, compiler_ops, facts, array_stores, instruction_ends
        )
        if first is None:
            index += 1
            continue
        file_result = _file_number(facts, by_end, instructions[index].offset)
        if file_result is None:
            index += 1
            continue
        file_number, start, file_support = file_result
        items = []
        cursor = index
        while item := _item(
            instructions, cursor, compiler_ops, facts, array_stores, instruction_ends
        ):
            items.append(item)
            cursor += item.size
        following = instructions[cursor] if cursor < len(instructions) else None
        has_numeric = any(item.kind != "string" for item in items)
        commit = following if following and _runtime_vector(following) == 0x87 else None
        incomplete_item = following is not None and _phase_name(following) in {
            "INPUT_FILE_NUMBER",
            "INPUT_FILE_STRING",
        }
        if incomplete_item or (has_numeric and commit is None) or following is None:
            index = cursor
            continue
        targets: list[tuple[object, ...]] = []
        support: list[tuple[int, ...]] = [file_support]
        for item in items:
            if isinstance(item.reference, int):
                target = resolve_slot(item.reference, facts) or resolve_array_element(
                    item.reference, facts
                )
                if target is None:
                    break
                if not isinstance(target.value, tuple):
                    break
                # A slot names its type; an array element's name already does.
                targets.append(
                    target.value + (item.kind,)
                    if target.value[:1] == ("slot",)
                    else target.value
                )
                support.extend((item.evidence, target.evidence))
            else:
                if not isinstance(item.reference, tuple):
                    break
                targets.append(item.reference)
                support.append(item.evidence)
        else:
            if commit is None:
                end = instructions[cursor - 1].end
            else:
                end = commit.end
                support.append((commit.offset,))
            yield Fact(
                "semantic.input_file",
                (start, end),
                (file_number, tuple(targets)),
                combine_evidence(*support),
                "anchored",
            )
        index = cursor + (1 if commit is not None else 0)


def _item(
    instructions: tuple[Operation, ...],
    index: int,
    compiler_ops: dict[int, CompilerOp],
    facts: frozenset[Fact],
    array_stores: dict[int, Fact] | None = None,
    instruction_ends: dict[int, int] | None = None,
) -> _Item | None:
    numeric = _numeric_item(instructions[index : index + 2])
    if numeric is not None:
        return numeric
    integer = integer_input_item(
        instructions[index : index + 5],
        compiler_ops,
        phase_name="INPUT_FILE_NUMBER",
    )
    if integer is not None and isinstance(integer.reference, int):
        return _Item(
            integer.size,
            integer.reference,
            integer.kind,
            integer.evidence,
        )
    array = array_input_item(
        instructions,
        index,
        facts,
        array_stores=array_stores,
        instruction_ends=instruction_ends,
        numeric_phase="INPUT_FILE_NUMBER",
        string_phase="INPUT_FILE_STRING",
    )
    if array is not None:
        return _Item(
            array.size,
            array.reference,
            array.kind,
            array.evidence,
        )
    return _string_item(instructions[index : index + 3])


@reads(
    "constant",
    "expression.system",
    "layout.array",
    "machine.store",
    "reference.array_store",
    "slot",
    "tb.runtime",
    "tb.statement",
    "x86.mov_imm",
)
def line_input_file_statement_facts(
    evidence: Evidence, facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Recover LINE INPUT statements reading from an open file."""
    instructions = evidence.instructions
    by_end = {instruction.end: instruction for instruction in instructions}
    for index, statement in enumerate(instructions):
        if statement.kind != "tb.statement" or statement.operands != (
            "LINE_INPUT_FILE",
            0x66,
        ):
            continue
        file_result = _file_number(facts, by_end, statement.offset)
        target = _line_input_target(instructions, index + 1, statement.end, facts)
        if file_result is None or target is None:
            continue
        file_number, start, file_support = file_result
        target_value, end, target_support = target
        yield Fact(
            "semantic.statement",
            (start, end),
            (
                "LINE_INPUT",
                0x66,
                file_number,
                None,
                target_value,
                False,
            ),
            combine_evidence(
                file_support,
                (statement.offset,),
                target_support,
            ),
            "anchored",
        )


def _line_input_target(
    instructions: tuple[Operation, ...],
    index: int,
    start: int,
    facts: frozenset[Fact],
) -> tuple[object, int, tuple[int, ...]] | None:
    tail = instructions[index : index + 2]
    if len(tail) == 2:
        setup, store = tail
        if (
            setup.kind == "x86.mov_imm"
            and setup.operands[:1] == ("si",)
            and len(setup.operands) == 2
            and isinstance(setup.operands[1], int)
            and setup.offset == start
            and setup.end == store.offset
            and _runtime_vector(store) == 0xA0
        ):
            target = resolve_slot(setup.operands[1], facts)
            if target is not None and isinstance(target.value, tuple):
                return (
                    target.value + ("string",),
                    store.end,
                    combine_evidence((setup.offset, store.offset), target.evidence),
                )
    arrays = [
        fact
        for fact in facts
        if fact.kind == "reference.array_store"
        and len(fact.subject) == 2
        and fact.subject[0] == start
        and len(fact.value) == 2
        and fact.value[1] == "string"
        and isinstance(fact.subject[1], int)
    ]
    if len(arrays) != 1:
        return None
    return arrays[0].value[0], arrays[0].subject[1], arrays[0].evidence


def _numeric_item(pair: tuple[Operation, ...]) -> _Item | None:
    if len(pair) != 2:
        return None
    phase, store = pair
    raw = bytes.fromhex(store.raw)
    if (
        _phase_name(phase) != "INPUT_FILE_NUMBER"
        or phase.end != store.offset
        or store.kind != "tb.fp"
        or len(raw) != 5
        or raw[0] != 0xCD
        or raw[2] != 0x1E
        or raw[1] not in FP_TRANSFER_TYPES
        or FP_TRANSFER_TYPES[raw[1]] == "integer"
    ):
        return None
    return _Item(
        2,
        struct.unpack_from("<H", raw, 3)[0],
        FP_TRANSFER_TYPES[raw[1]],
        (phase.offset, store.offset),
    )


def _string_item(window: tuple[Operation, ...]) -> _Item | None:
    if len(window) != 3:
        return None
    phase, setup, store = window
    if (
        _phase_name(phase) != "INPUT_FILE_STRING"
        or phase.end != setup.offset
        or setup.kind != "x86.mov_imm"
        or len(setup.operands) != 2
        or setup.operands[0] != "si"
        or not isinstance(setup.operands[1], int)
        or setup.end != store.offset
        or _runtime_vector(store) != 0xA0
    ):
        return None
    return _Item(3, setup.operands[1], "string", tuple(x.offset for x in window))


def _file_number(
    facts: frozenset[Fact],
    by_end: dict[int, Operation],
    start: int,
) -> tuple[object, int, tuple[int, ...]] | None:
    store = by_end.get(start)
    if store is None:
        return None
    effects = [
        fact
        for fact in facts
        if fact.kind == "machine.store"
        and fact.subject == (0x60,)
        and fact.evidence
        and fact.evidence[-1] == store.offset
        and len(fact.value) == 1
    ]
    if len(effects) != 1:
        return None
    resolved = resolve_expression(effects[0].value[0], facts)
    if resolved is None:
        return None
    value = resolved.value
    if isinstance(value, tuple) and value[:1] == ("const",):
        value = value[1]
    return (
        value,
        effects[0].evidence[0],
        combine_evidence(effects[0].evidence, resolved.evidence),
    )


INPUT_FILE_FACT_PASSES: tuple[NamedPass, ...] = (
    ("input-file", input_file_statement_facts),
    ("line-input-file", line_input_file_statement_facts),
)
