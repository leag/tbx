"""Scalar INPUT # facts over complete file-item chains."""

from __future__ import annotations

import struct
from collections.abc import Iterable
from dataclasses import dataclass

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
    address: int
    kind: str
    evidence: tuple[int, ...]


def input_file_statement_facts(
    evidence: Evidence, facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Recover scalar INPUT # chains with a resolved file-number store."""

    instructions = evidence.instructions
    by_end = {instruction.end: instruction for instruction in instructions}
    index = 0
    while index < len(instructions):
        first = _item(instructions, index)
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
        while item := _item(instructions, cursor):
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
        targets = []
        support = [file_support]
        for item in items:
            target = resolve_slot(item.address, facts) or resolve_array_element(
                item.address, facts
            )
            if target is None:
                break
            targets.append(target.value + (item.kind,))
            support.extend((item.evidence, target.evidence))
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


def _item(instructions: tuple[Operation, ...], index: int) -> _Item | None:
    numeric = _numeric_item(instructions[index : index + 2])
    return numeric if numeric is not None else _string_item(
        instructions[index : index + 3]
    )


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
    return value, effects[0].evidence[0], combine_evidence(
        effects[0].evidence, resolved.evidence
    )


def _phase_name(instruction: Operation) -> str | None:
    if instruction.kind != "tb.statement" or not instruction.operands:
        return None
    name = instruction.operands[0]
    return name if isinstance(name, str) else None


def _runtime_vector(instruction: Operation) -> int | None:
    if instruction.kind != "tb.runtime" or not instruction.operands:
        return None
    vector = instruction.operands[0]
    return vector if isinstance(vector, int) else None


INPUT_FILE_FACT_PASSES: tuple[NamedPass, ...] = (
    ("input-file", input_file_statement_facts),
)
