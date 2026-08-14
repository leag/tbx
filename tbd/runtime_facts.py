"""Turbo Basic runtime-chain facts over immutable instructions."""

from __future__ import annotations

import struct
from collections.abc import Iterable
from dataclasses import dataclass

from tbd.facts import Evidence, NamedPass
from tbd.ir import Fact, Operation
from tbd.semantic import combine_evidence, resolve_expression

_NUMERIC_ITEMS = {0xBB: "console", 0xBD: "file", 0xBC: "printer"}
_STRING_ITEMS = {0xBE: "console", 0xC0: "file", 0xBF: "printer"}
_FLUSHES = {0xB8: "console", 0xBA: "file", 0xB9: "printer"}
_SEPARATORS = {0xC1: "console", 0xC3: "file", 0xC2: "printer"}
_CONTROL_ITEMS = {
    0xC7: ("TAB", "console"),
    0xC9: ("TAB", "file"),
    0xC8: ("TAB", "printer"),
    0xC4: ("SPC", "console"),
    0xC6: ("SPC", "file"),
    0xC5: ("SPC", "printer"),
}
_UNRESOLVED_CONTROLS = {vector: mode for vector, (_name, mode) in _CONTROL_ITEMS.items()}


@dataclass(frozen=True)
class _Item:
    start: int
    end: int
    mode: str
    value: object
    evidence: tuple[int, ...]


@dataclass(frozen=True)
class _Chain:
    start: int
    items: tuple[_Item, ...]
    evidence: tuple[int, ...]


def runtime_facts(
    evidence: Evidence, facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Resolve complete PRINT chains without consuming their instructions."""

    expressions = _expression_index(facts, evidence.instructions)
    items = _print_items(evidence.instructions, expressions, facts)
    by_end = {item.end: item for item in items}
    instructions_by_end = {
        instruction.end: instruction for instruction in evidence.instructions
    }
    separators = {
        instruction.end: instruction
        for instruction in evidence.instructions
        if _runtime_vector(instruction) in _SEPARATORS
    }
    for instruction in evidence.instructions:
        mode = _FLUSHES.get(_runtime_vector(instruction))
        if mode is None:
            continue
        chain = _item_chain(by_end, separators, instruction.offset, mode)
        if not chain or _has_preceding_item(instructions_by_end, chain.start, mode):
            continue
        values = tuple(item.value for item in chain.items)
        support = combine_evidence(
            *(item.evidence for item in chain.items),
            chain.evidence,
            (instruction.offset,),
        )
        yield Fact(
            "semantic.lprint" if mode == "printer" else "semantic.print",
            (chain.start, instruction.end),
            (mode, values, True),
            support,
            "anchored",
        )


def _expression_index(
    facts: frozenset[Fact], instructions: tuple[Operation, ...]
) -> dict[int, Fact]:
    ends = {instruction.offset: instruction.end for instruction in instructions}
    candidates: dict[int, list[Fact]] = {}
    for fact in facts:
        if fact.kind != "expression.value" or not fact.evidence:
            continue
        end = ends.get(fact.evidence[-1])
        if end is not None:
            candidates.setdefault(end, []).append(fact)
    return {
        end: matches[0]
        for end, matches in candidates.items()
        if len(matches) == 1
    }


def _print_items(
    instructions: tuple[Operation, ...],
    expressions: dict[int, Fact],
    facts: frozenset[Fact],
) -> tuple[_Item, ...]:
    result = []
    for index, instruction in enumerate(instructions):
        if item := _numeric_item(instruction, expressions, facts):
            result.append(item)
        if item := _string_item(instructions[index : index + 3], facts):
            result.append(item)
        if item := _control_item(instructions[index : index + 2]):
            result.append(item)
        if item := _bridged_control(instructions[index : index + 4], facts):
            result.append(item)
    return tuple(result)


def _numeric_item(
    runtime: Operation,
    expressions: dict[int, Fact],
    facts: frozenset[Fact],
) -> _Item | None:
    mode = _NUMERIC_ITEMS.get(_runtime_vector(runtime))
    expression = expressions.get(runtime.offset)
    if mode is None or expression is None:
        return None
    resolved = resolve_expression(expression.value[0], facts)
    if resolved is None:
        return None
    support = combine_evidence(expression.evidence, resolved.evidence, (runtime.offset,))
    return _Item(expression.evidence[0], runtime.end, mode, resolved.value, support)


def _string_item(
    window: tuple[Operation, ...], facts: frozenset[Fact]
) -> _Item | None:
    if len(window) != 3:
        return None
    setup, read, runtime = window
    mode = _STRING_ITEMS.get(_runtime_vector(runtime))
    if not _is_string_setup(setup, read) or mode is None:
        return None
    resolved = resolve_expression(
        ("memory", setup.operands[1], "string"), facts
    )
    if resolved is None:
        return None
    support = combine_evidence(
        (setup.offset, read.offset, runtime.offset), resolved.evidence
    )
    return _Item(setup.offset, runtime.end, mode, resolved.value, support)


def _control_item(pair: tuple[Operation, ...]) -> _Item | None:
    if len(pair) != 2:
        return None
    load, runtime = pair
    control = _CONTROL_ITEMS.get(_runtime_vector(runtime))
    if (
        control is None
        or load.kind != "x86.mov_imm"
        or load.operands[:1] != ("ax",)
        or len(load.operands) != 2
        or load.end != runtime.offset
    ):
        return None
    name, mode = control
    value = "call", name, (("const", load.operands[1]),)
    return _Item(
        load.offset,
        runtime.end,
        mode,
        value,
        (load.offset, runtime.offset),
    )


def _bridged_control(
    window: tuple[Operation, ...], facts: frozenset[Fact]
) -> _Item | None:
    if len(window) != 4:
        return None
    source, store, reload, runtime = window
    control = _CONTROL_ITEMS.get(_runtime_vector(runtime))
    address = _fp_ax_reload(reload)
    if control is None or address is None or not _contiguous(window):
        return None
    effects = [
        fact
        for fact in facts
        if fact.kind == "machine.store"
        and fact.subject == (address,)
        and fact.evidence == (source.offset, store.offset)
        and len(fact.value) == 1
    ]
    if len(effects) != 1:
        return None
    resolved = resolve_expression(effects[0].value[0], facts)
    if resolved is None:
        return None
    name, mode = control
    value = "call", name, (resolved.value,)
    support = combine_evidence(
        tuple(instruction.offset for instruction in window),
        effects[0].evidence,
        resolved.evidence,
    )
    return _Item(source.offset, runtime.end, mode, value, support)


def _fp_ax_reload(instruction: Operation) -> int | None:
    raw = bytes.fromhex(instruction.raw)
    if instruction.kind != "tb.fp" or len(raw) != 5 or raw[:3] != b"\xcd\x3d\xa1":
        return None
    return struct.unpack_from("<H", raw, 3)[0]


def _contiguous(instructions: tuple[Operation, ...]) -> bool:
    return all(
        left.end == right.offset
        for left, right in zip(instructions, instructions[1:])
    )


def _item_chain(
    by_end: dict[int, _Item],
    separators: dict[int, Operation],
    end: int,
    mode: str,
) -> _Chain | None:
    reverse = []
    support = []
    cursor = end
    start = end
    while True:
        item = by_end.get(cursor)
        if item is not None and item.mode == mode:
            reverse.append(item)
            cursor = start = item.start
            continue
        separator = separators.get(cursor)
        if (
            separator is not None
            and _SEPARATORS[_runtime_vector(separator)] == mode
        ):
            support.append(separator.offset)
            cursor = start = separator.offset
            continue
        break
    if not reverse:
        return None
    return _Chain(start, tuple(reversed(reverse)), tuple(support))


def _has_preceding_item(
    instructions_by_end: dict[int, Operation], start: int, mode: str
) -> bool:
    previous = instructions_by_end.get(start)
    vector = _runtime_vector(previous) if previous is not None else None
    preceding_mode = _NUMERIC_ITEMS.get(
        vector, _STRING_ITEMS.get(vector, _UNRESOLVED_CONTROLS.get(vector))
    )
    return preceding_mode == mode


def _is_string_setup(setup: Operation, read: Operation) -> bool:
    return (
        setup.kind == "x86.mov_imm"
        and setup.operands[0] == "si"
        and _runtime_vector(read) == 0x9C
        and setup.end == read.offset
    )


def _runtime_vector(instruction: Operation) -> int | None:
    if instruction.kind != "tb.runtime" or not instruction.operands:
        return None
    vector = instruction.operands[0]
    return vector if isinstance(vector, int) else None


RUNTIME_FACT_PASSES: tuple[NamedPass, ...] = (("runtime", runtime_facts),)
