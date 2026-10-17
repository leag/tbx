from __future__ import annotations

import struct
from collections.abc import Iterable
from dataclasses import dataclass

from tbd.compiler_ops import CompilerOp, translate_operations
from tbd.facts import Evidence, NamedPass, reads
from tbd.input_facts import _array_stores_by_start, array_input_item, integer_input_item
from tbd.ir import Fact, Operation
from tbd.operation_helpers import statement_name as _phase_name
from tbd.profile import FP_TRANSFER_TYPES
from tbd.semantic import combine_evidence, resolve_array_element, resolve_slot


@dataclass(frozen=True)
class _Item:
    size: int
    reference: object
    kind: str
    evidence: tuple[int, ...]


@reads(
    "layout.array",
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
def read_statement_facts(evidence: Evidence, facts: frozenset[Fact]) -> Iterable[Fact]:
    """Recover READ statements and their typed destinations."""

    instructions = evidence.instructions
    compiler_ops = {
        operation.offset: operation for operation in translate_operations(instructions)
    }
    array_stores = _array_stores_by_start(facts)
    instruction_ends = {item.end: index for index, item in enumerate(instructions)}
    index = 0
    while index < len(instructions):
        first = _item(
            instructions, index, compiler_ops, facts, array_stores, instruction_ends
        )
        if first is None:
            index += 1
            continue
        items = []
        cursor = index
        while item := _item(
            instructions, cursor, compiler_ops, facts, array_stores, instruction_ends
        ):
            items.append(item)
            cursor += item.size
        following = instructions[cursor] if cursor < len(instructions) else None
        has_numeric = any(item.kind != "string" for item in items)
        commit = following if _runtime_vector(following) == 0x87 else None
        incomplete = following is not None and _phase_name(following) in {
            "DATA_NUMBER",
            "DATA_STRING",
        }
        if incomplete or (has_numeric and commit is None):
            index = cursor
            continue
        targets: list[object] = []
        support: list[tuple[int, ...]] = []
        for item in items:
            if isinstance(item.reference, int):
                target = resolve_slot(item.reference, facts) or resolve_array_element(
                    item.reference, facts
                )
                if target is None:
                    break
                if not isinstance(target.value, tuple):
                    break
                targets.append(target.value + (item.kind,))
                support.extend((item.evidence, target.evidence))
            else:
                targets.append(item.reference)
                support.append(item.evidence)
        else:
            end = commit.end if commit is not None else instructions[cursor - 1].end
            yield Fact(
                "semantic.read",
                (instructions[index].offset, end),
                (tuple(targets),),
                combine_evidence(
                    *support,
                    () if commit is None else (commit.offset,),
                ),
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
        phase_name="DATA_NUMBER",
    )
    if integer is not None:
        return _Item(integer.size, integer.reference, integer.kind, integer.evidence)
    array = array_input_item(
        instructions,
        index,
        facts,
        array_stores=array_stores,
        instruction_ends=instruction_ends,
        numeric_phase="DATA_NUMBER",
        string_phase="DATA_STRING",
    )
    if array is not None:
        return _Item(array.size, array.reference, array.kind, array.evidence)
    return _string_item(instructions[index : index + 3])


def _numeric_item(pair: tuple[Operation, ...]) -> _Item | None:
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
        _phase_name(phase) != "DATA_STRING"
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


def _runtime_vector(instruction: Operation | None) -> int | None:
    if (
        instruction is None
        or instruction.kind != "tb.runtime"
        or not instruction.operands
    ):
        return None
    vector = instruction.operands[0]
    return vector if isinstance(vector, int) else None


READ_FACT_PASSES: tuple[NamedPass, ...] = (("read", read_statement_facts),)
