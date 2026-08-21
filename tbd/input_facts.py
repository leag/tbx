"""Console INPUT facts over complete direct-target chains."""

from __future__ import annotations

import struct
from collections.abc import Iterable
from dataclasses import dataclass

from tbd.compiler_ops import CompilerOp, translate_operations
from tbd.facts import Evidence, NamedPass
from tbd.ir import Fact, Operation
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


def input_statement_facts(
    evidence: Evidence, facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Recover complete scalar INPUT chains justified by their header flags."""

    instructions = evidence.instructions
    compiler_ops = {
        operation.offset: operation
        for operation in translate_operations(instructions)
    }
    for index, header in enumerate(instructions):
        parsed = _header(header)
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
            item = _item(instructions, cursor, compiler_ops, facts)
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
        prompt = _prompt(prompt_address, facts)
        if prompt is None:
            continue
        prompt_value, prompt_evidence = prompt
        targets = []
        target_evidence = []
        for item in items:
            if isinstance(item.reference, int):
                target = resolve_slot(
                    item.reference, facts
                ) or resolve_array_element(item.reference, facts)
                if target is None:
                    break
                target_value, support = target.value, target.evidence
            else:
                target_value, support = item.reference, ()
            targets.append(
                target_value + (item.kind,)
                if isinstance(item.reference, int)
                else target_value
            )
            target_evidence.extend((item.evidence, support))
        else:
            end_address = commit.end if has_numeric and commit is not None else (
                instructions[cursor - 1].end
            )
            value = targets[0] if count == 1 else tuple(targets)
            support = combine_evidence(
                (header.offset,),
                prompt_evidence,
                *target_evidence,
                () if not has_numeric else (commit.offset,),
            )
            yield Fact(
                "semantic.input",
                (header.offset, end_address),
                (prompt_value, value, bool(flags & 0x40), bool(flags & 0x80)),
                support,
                "anchored",
            )


def _header(instruction: Operation) -> tuple[int, int, int] | None:
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


def _item(
    instructions: tuple[Operation, ...],
    index: int,
    compiler_ops: dict[int, CompilerOp],
    facts: frozenset[Fact],
) -> _Item | None:
    numeric = _numeric_item(instructions[index : index + 2])
    if numeric is not None:
        return numeric
    integer = integer_input_item(instructions[index : index + 5], compiler_ops)
    if integer is not None:
        return integer
    array = _array_item(instructions, index, facts)
    return array if array is not None else _string_item(instructions[index : index + 3])


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
    """Port tbx's calibrated FP-to-INTEGER INPUT scratch bridge."""

    if len(window) != 5 or _phase_name(window[0]) != phase_name:
        return None
    operations = tuple(compiler_ops.get(item.offset) for item in window[1:])
    if any(operation is None for operation in operations):
        return None
    convert, sync, load, store = operations
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


def _string_item(window: tuple[Operation, ...]) -> _Item | None:
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
        or _runtime_vector(store) != 0xA0
    ):
        return None
    return _Item(
        3,
        setup.operands[1],
        "string",
        (phase.offset, setup.offset, store.offset),
    )


def _array_item(
    instructions: tuple[Operation, ...], index: int, facts: frozenset[Fact]
) -> _Item | None:
    if index >= len(instructions):
        return None
    phase = instructions[index]
    matches = [
        fact
        for fact in facts
        if fact.kind == "reference.array_store"
        and len(fact.subject) == 2
        and fact.subject[0] == phase.end
        and len(fact.value) == 2
        and isinstance(fact.value[1], str)
    ]
    if len(matches) != 1:
        return None
    match = matches[0]
    kind = match.value[1]
    expected_phase = "READ_STRING" if kind == "string" else "READ_NUMBER"
    if _phase_name(phase) != expected_phase:
        return None
    terminal = next(
        (
            position
            for position in range(index + 1, len(instructions))
            if instructions[position].end == match.subject[1]
        ),
        None,
    )
    if terminal is None:
        return None
    return _Item(
        terminal - index + 1,
        match.value[0],
        kind,
        combine_evidence((phase.offset,), match.evidence),
    )


def _prompt(
    address: int, facts: frozenset[Fact]
) -> tuple[object, tuple[int, ...]] | None:
    layouts = [
        fact
        for fact in facts
        if fact.kind == "layout.pool"
        and fact.subject == ("dgroup",)
        and len(fact.value) == 4
        and isinstance(fact.value[1], int)
    ]
    if len(layouts) != 1:
        return None
    layout = layouts[0]
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


def _phase_name(instruction: Operation) -> str | None:
    if instruction.kind != "tb.statement" or not instruction.operands:
        return None
    name = instruction.operands[0]
    return name if isinstance(name, str) else None


def _runtime_vector(instruction: Operation | None) -> int | None:
    if instruction is None or instruction.kind != "tb.runtime":
        return None
    vector = instruction.operands[0] if instruction.operands else None
    return vector if isinstance(vector, int) else None


INPUT_FACT_PASSES: tuple[NamedPass, ...] = (("input", input_statement_facts),)
