from __future__ import annotations

import struct
from collections.abc import Iterable
from dataclasses import dataclass
from typing import cast

from tbd.compiler_ops import CompilerOp, translate_operations
from tbd.facts import Evidence, NamedPass, reads
from tbd.ir import Fact, Operation
from tbd.operation_helpers import statement_name as _phase_name
from tbd.profile import FP_TRANSFER_TYPES
from tbd.semantic import (
    agreeing_fact,
    combine_evidence,
    function_parameter_at,
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
    "layout.pool",
    "reference.array_store",
    "semantic.def_fn",
    "signature",
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
def input_statement_facts(evidence: Evidence, facts: frozenset[Fact]) -> Iterable[Fact]:
    """Recover INPUT statements and their destination variables."""

    instructions = evidence.instructions
    array_stores = _array_stores_by_start(facts)
    instruction_ends = {item.end: index for index, item in enumerate(instructions)}
    compiler_ops = {
        operation.offset: operation for operation in translate_operations(instructions)
    }
    for index, header in enumerate(instructions):
        parsed = input_header(header)
        if parsed is None:
            continue
        prompt_address, flags, count = parsed
        yield Fact(
            "reference.input_prompt",
            (prompt_address,),
            ("string",),
            (header.offset,),
            "signature",
        )
        items = []
        cursor = index + 1
        for item_index in range(count):
            item = _item(
                instructions,
                cursor,
                compiler_ops,
                facts,
                array_stores,
                instruction_ends,
            )
            if item is None or _type_bit_mismatch(flags, item_index, item.kind):
                break
            items.append(item)
            cursor += item.size
        if len(items) != count:
            continue
        has_numeric = any(item.kind != "string" for item in items)
        commit = instructions[cursor] if cursor < len(instructions) else None
        if has_numeric and _runtime_vector(commit) != 0x87:
            continue
        prompt = input_prompt(prompt_address, facts)
        if prompt is None:
            continue
        prompt_value, prompt_evidence = prompt
        targets: list[object] = []
        target_evidence: list[tuple[int, ...]] = []
        for item in items:
            if isinstance(item.reference, int):
                target = resolve_slot(item.reference, facts) or resolve_array_element(
                    item.reference, facts
                )
                if target is None:
                    break
                target_value, support = target.value, target.evidence
            else:
                target_value, support = item.reference, ()
            if isinstance(item.reference, int):
                if not isinstance(target_value, tuple):
                    break
                targets.append(target_value + (item.kind,))
            else:
                targets.append(target_value)
            target_evidence.extend((item.evidence, support))
        else:
            end_address = (
                commit.end
                if has_numeric and commit is not None
                else (instructions[cursor - 1].end)
            )
            value = targets[0] if count == 1 else tuple(targets)
            if has_numeric and commit is None:
                continue
            support = combine_evidence(
                (header.offset,),
                prompt_evidence,
                *target_evidence,
                () if not has_numeric or commit is None else (commit.offset,),
            )
            yield Fact(
                "semantic.input",
                (header.offset, end_address),
                (prompt_value, value, bool(flags & 0x40), bool(flags & 0x80)),
                support,
                "anchored",
            )


def input_header(instruction: Operation) -> tuple[int, int, int] | None:
    """Decode the runtime header describing an INPUT operation."""
    if (
        instruction.kind != "tb.statement"
        or len(instruction.operands) != 4
        or instruction.operands[:2] != ("INPUT", 0x4E)
        or not isinstance(instruction.operands[2], int)
        or not isinstance(instruction.operands[3], int)
    ):
        return None
    prompt, flags = instruction.operands[2:]
    count = (flags & 0x3F) + 1
    type_mask = sum(0x4000 >> index for index in range(count))
    if flags & ~(0x00C0 | 0x3F | type_mask):
        return None
    return prompt, flags, count


@reads(
    "constant",
    "expression.system",
    "layout.array",
    "layout.pool",
    "reference.array_store",
    "signature",
    "slot",
    "tb.runtime",
    "tb.statement",
    "x86.mov_imm",
)
def line_input_statement_facts(
    evidence: Evidence, facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Recover LINE INPUT statements from their runtime scaffold."""
    instructions = evidence.instructions
    for index, header in enumerate(instructions):
        if (
            header.kind != "tb.statement"
            or len(header.operands) != 4
            or header.operands[:2] != ("LINE_INPUT", 0x64)
            or not isinstance(header.operands[2], int)
            or header.operands[3] not in {0x40, 0xC0}
        ):
            continue
        prompt_address, flags = header.operands[2:]
        yield Fact(
            "reference.input_prompt",
            (prompt_address,),
            ("string",),
            (header.offset,),
            "signature",
        )
        prompt = input_prompt(prompt_address, facts)
        if prompt is None:
            continue
        prompt_value, prompt_support = prompt
        target = _line_input_target(instructions, index, header, facts)
        if target is None:
            continue
        target_value, end, target_support = target
        yield Fact(
            "semantic.statement",
            (header.offset, end),
            ("LINE_INPUT", 0x64, None, prompt_value, target_value, bool(flags & 0x80)),
            combine_evidence((header.offset,), prompt_support, target_support),
            "anchored",
        )


def _line_input_target(
    instructions: tuple[Operation, ...],
    index: int,
    header: Operation,
    facts: frozenset[Fact],
) -> tuple[object, int, tuple[int, ...]] | None:
    """Return the variable a console LINE INPUT stores, its end and evidence.

    A scalar is stored with ``mov si,var; int A0h`` right after the header; an
    array element's address is computed first and its string store begins
    where the header ends.
    """
    tail = instructions[index + 1 : index + 3]
    if len(tail) == 2:
        setup, store = tail
        if (
            setup.kind == "x86.mov_imm"
            and setup.operands[:1] == ("si",)
            and len(setup.operands) == 2
            and isinstance(setup.operands[1], int)
            and header.end == setup.offset
            and setup.end == store.offset
            and _runtime_vector(store) == 0xA0
        ):
            target = resolve_slot(setup.operands[1], facts)
            if target is None:
                return None
            value = (
                target.value + ("string",)
                if isinstance(target.value, tuple)
                else target.value
            )
            return (
                value,
                store.end,
                combine_evidence((setup.offset, store.offset), target.evidence),
            )
    elements = {
        fact
        for fact in facts
        if fact.kind == "reference.array_store"
        and len(fact.subject) == 2
        and fact.subject[0] == header.end
        and len(fact.value) == 2
        and fact.value[1] == "string"
    }
    if len({fact.value[0] for fact in elements}) != 1:
        return None
    element = min(elements, key=lambda fact: (fact.subject, fact.evidence))
    return element.value[0], element.subject[1], element.evidence


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
    integer = integer_input_item(instructions[index : index + 5], compiler_ops)
    if integer is not None:
        return integer
    array = array_input_item(
        instructions,
        index,
        facts,
        array_stores=array_stores,
        instruction_ends=instruction_ends,
    )
    return (
        array
        if array is not None
        else _string_item(instructions[index : index + 3], facts)
    )


def _numeric_item(pair: tuple[Operation, ...]) -> _Item | None:
    if len(pair) != 2:
        return None
    phase, store = pair
    raw = bytes.fromhex(store.raw)
    if (
        _phase_name(phase) != "READ_NUMBER"
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


def integer_input_item(
    window: tuple[Operation, ...],
    compiler_ops: dict[int, CompilerOp],
    *,
    phase_name: str = "READ_NUMBER",
) -> _Item | None:
    """Recognize an integer destination in an INPUT item window."""

    if len(window) != 5 or _phase_name(window[0]) != phase_name:
        return None
    operations = tuple(compiler_ops.get(item.offset) for item in window[1:])
    if any(operation is None for operation in operations):
        return None
    convert, sync, load, store = cast(tuple[CompilerOp, ...], operations)
    if (
        convert.kind != "fistp"
        or convert.args != (0x2C,)
        or sync.kind != "fwait"
        or load.kind != "movaxmem"
        or load.args != (0x2C,)
        or store.kind != "movm_ax"
        or len(store.args) != 1
        or not isinstance(store.args[0], int)
        or any(left.end != right.offset for left, right in zip(window, window[1:]))
    ):
        return None
    return _Item(
        5,
        store.args[0],
        "integer",
        tuple(item.offset for item in window),
    )


def _string_item(window: tuple[Operation, ...], facts: frozenset[Fact]) -> _Item | None:
    if len(window) != 3:
        return None
    phase, setup, store = window
    if (
        _phase_name(phase) != "READ_STRING"
        or phase.end != setup.offset
        or setup.kind != "x86.mov_imm"
        or len(setup.operands) != 2
        or setup.operands[0] != "si"
        or not isinstance(setup.operands[1], int)
        or setup.end != store.offset
        or _runtime_vector(store) not in {0xA0, 0xA2}
    ):
        return None
    reference: object = setup.operands[1]
    if _runtime_vector(store) == 0xA2:
        reference = function_parameter_at(
            facts,
            phase.offset,
            setup.operands[1],
            "string",
        )
        if reference is None:
            return None
    return _Item(
        3,
        reference,
        "string",
        (phase.offset, setup.offset, store.offset),
    )


def array_input_item(
    instructions: tuple[Operation, ...],
    index: int,
    facts: frozenset[Fact],
    *,
    numeric_phase: str = "READ_NUMBER",
    string_phase: str = "READ_STRING",
    array_stores: dict[int, Fact] | None = None,
    instruction_ends: dict[int, int] | None = None,
) -> _Item | None:
    """Recognize an array destination in an INPUT item window."""
    if index >= len(instructions):
        return None
    phase = instructions[index]
    if array_stores is None:
        array_stores = _array_stores_by_start(facts)
    match = array_stores.get(phase.end)
    if match is None:
        return None
    kind = match.value[1]
    expected_phase = string_phase if kind == "string" else numeric_phase
    if _phase_name(phase) != expected_phase:
        return None
    if instruction_ends is None:
        instruction_ends = {
            item.end: position for position, item in enumerate(instructions)
        }
    terminal = instruction_ends.get(match.subject[1])
    if terminal is None:
        return None
    return _Item(
        terminal - index + 1,
        match.value[0],
        kind,
        combine_evidence((phase.offset,), match.evidence),
    )


def _array_stores_by_start(facts: frozenset[Fact]) -> dict[int, Fact]:
    matches = [
        fact
        for fact in facts
        if fact.kind == "reference.array_store"
        and len(fact.subject) == 2
        and len(fact.value) == 2
        and isinstance(fact.value[1], str)
    ]
    starts = {fact.subject[0] for fact in matches}
    return {
        start: fact
        for start in starts
        if len([item for item in matches if item.subject[0] == start]) == 1
        for fact in matches
        if fact.subject[0] == start
    }


def input_prompt(
    address: int, facts: frozenset[Fact]
) -> tuple[object, tuple[int, ...]] | None:
    """Resolve the optional prompt expression preceding an INPUT header."""
    layout = agreeing_fact(facts, "layout.pool", ("dgroup",))
    if layout is None or len(layout.value) != 4 or not isinstance(layout.value[1], int):
        return None
    if address == layout.value[1] - 4:
        return None, layout.evidence
    resolved = resolve_expression(("memory", address, "string"), facts)
    if (
        resolved is None
        or not isinstance(resolved.value, tuple)
        or resolved.value[:1] != ("string",)
    ):
        return None
    return resolved.value, resolved.evidence


def _type_bit_mismatch(flags: int, index: int, kind: str) -> bool:
    return bool(flags & (0x4000 >> index)) == (kind == "string")


def _runtime_vector(instruction: Operation | None) -> int | None:
    if instruction is None or instruction.kind != "tb.runtime":
        return None
    vector = instruction.operands[0] if instruction.operands else None
    return vector if isinstance(vector, int) else None


INPUT_FACT_PASSES: tuple[NamedPass, ...] = (
    ("input", input_statement_facts),
    ("line-input", line_input_statement_facts),
)
