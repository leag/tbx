"""Numeric READ facts over complete committed item chains."""

from __future__ import annotations

import struct
from collections.abc import Iterable

from tbd.facts import Evidence, NamedPass
from tbd.ir import Fact, Operation
from tbd.profile import FP_TRANSFER_TYPES
from tbd.semantic import combine_evidence, resolve_array_element, resolve_slot


def read_statement_facts(
    evidence: Evidence, facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Recover maximal numeric-only READ chains with their commit."""

    instructions = evidence.instructions
    index = 0
    while index + 1 < len(instructions):
        first = _numeric_item(instructions[index : index + 2])
        if first is None or _preceded_by_string_item(instructions, index):
            index += 1
            continue
        items = []
        cursor = index
        while item := _numeric_item(instructions[cursor : cursor + 2]):
            items.append(item)
            cursor += 2
        commit = instructions[cursor] if cursor < len(instructions) else None
        if commit is None or _runtime_vector(commit) != 0x87:
            index = cursor
            continue
        targets = []
        support = [item[2] for item in items]
        for address, kind, _item_support in items:
            target = resolve_slot(address, facts) or resolve_array_element(
                address, facts
            )
            if target is None:
                break
            targets.append(target.value + (kind,))
            support.append(target.evidence)
        else:
            yield Fact(
                "semantic.read",
                (instructions[index].offset, commit.end),
                (tuple(targets),),
                combine_evidence(*support, (commit.offset,)),
                "anchored",
            )
        index = cursor + 1


def _numeric_item(
    pair: tuple[Operation, ...],
) -> tuple[int, str, tuple[int, ...]] | None:
    if len(pair) != 2:
        return None
    phase, store = pair
    raw = bytes.fromhex(store.raw)
    if (
        _phase_name(phase) != "DATA_NUMBER"
        or phase.end != store.offset
        or store.kind != "tb.fp"
        or len(raw) != 5
        or raw[0] != 0xCD
        or raw[2] != 0x1E
        or raw[1] not in FP_TRANSFER_TYPES
    ):
        return None
    return (
        struct.unpack_from("<H", raw, 3)[0],
        FP_TRANSFER_TYPES[raw[1]],
        (phase.offset, store.offset),
    )


def _preceded_by_string_item(
    instructions: tuple[Operation, ...], index: int
) -> bool:
    if index < 3:
        return False
    phase, setup, store = instructions[index - 3 : index]
    return (
        _phase_name(phase) == "DATA_STRING"
        and phase.end == setup.offset
        and setup.kind == "x86.mov_imm"
        and len(setup.operands) == 2
        and setup.operands[0] == "si"
        and setup.end == store.offset
        and _runtime_vector(store) == 0xA0
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


READ_FACT_PASSES: tuple[NamedPass, ...] = (("numeric-read", read_statement_facts),)
