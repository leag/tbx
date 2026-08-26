"""Source-shaped assignment facts resolved from additive machine facts."""

from __future__ import annotations

import struct
from collections.abc import Iterable

from tbd.compiler_ops import translate_operations
from tbd.facts import Evidence, NamedPass
from tbd.ir import Fact, Operation
from tbd.semantic import (
    Resolved,
    combine_evidence,
    resolve_array_element,
    resolve_expression,
    resolve_expression_before,
    resolve_slot,
)


def assignment_facts(
    evidence: Evidence, facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Resolve complete stores and updates into source-shaped assignments."""

    instructions = {
        instruction.offset: instruction for instruction in evidence.instructions
    }
    instruction_ends = {
        instruction.offset: instruction.end for instruction in evidence.instructions
    }
    targets: dict[object, Resolved | None] = {}
    values: dict[tuple[object, ...], Resolved | None] = {}
    for effect in facts:
        if effect.kind not in {"machine.store", "machine.update"}:
            continue
        assignment = _assignment(
            effect, facts, instructions, instruction_ends, targets, values
        )
        if assignment is not None:
            yield assignment
    yield from _computed_array_assignments(evidence.instructions, facts)
    yield from _computed_value_assignments(evidence.instructions, facts)
    yield from _string_function_assignments(evidence.instructions, facts)
    yield from _direct_fp_function_assignments(evidence.instructions, facts)


def _direct_fp_function_assignments(
    instructions: tuple[Operation, ...], facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Store a proven AX-argument intrinsic's direct FP result."""

    by_offset = {instruction.offset: instruction for instruction in instructions}
    for expression in facts:
        if (
            expression.kind != "expression.value"
            or len(expression.value) != 1
            or not isinstance(expression.value[0], tuple)
            or expression.value[0][:2] != ("call", "LOC")
            or not expression.evidence
        ):
            continue
        call = by_offset.get(expression.evidence[-1])
        store = by_offset.get(call.end) if call is not None else None
        raw = bytes.fromhex(store.raw) if store is not None else b""
        if (
            store is None
            or store.kind != "tb.fp"
            or len(raw) != 5
            or raw[:3] != b"\xcd\x35\x1e"
        ):
            continue
        address = struct.unpack_from("<H", raw, 3)[0]
        target = resolve_slot(address, facts)
        if target is None:
            continue
        yield Fact(
            "semantic.assign",
            (expression.subject[0], store.end),
            (target.value, expression.value[0]),
            combine_evidence(
                expression.evidence,
                target.evidence,
                (store.offset,),
            ),
            "anchored",
        )


def _string_function_assignments(
    instructions: tuple[Operation, ...], facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Store one proven string-stack function result into its target slot."""

    by_offset = {instruction.offset: instruction for instruction in instructions}
    for expression in facts:
        if (
            expression.kind != "expression.value"
            or expression.value != (("call", "INKEY$", ()),)
            or not expression.evidence
        ):
            continue
        source = by_offset.get(expression.evidence[-1])
        setup = by_offset.get(source.end) if source is not None else None
        store = by_offset.get(setup.end) if setup is not None else None
        if (
            setup is None
            or setup.kind != "x86.mov_imm"
            or setup.operands[:1] != ("si",)
            or len(setup.operands) != 2
            or store is None
            or store.kind != "tb.runtime"
            or store.operands != (0xA0,)
        ):
            continue
        target = resolve_slot(setup.operands[1], facts)
        if target is None:
            continue
        yield Fact(
            "semantic.assign",
            (source.offset, store.end),
            (target.value, expression.value[0]),
            combine_evidence(
                expression.evidence,
                target.evidence,
                (setup.offset, store.offset),
            ),
            "anchored",
        )


def _computed_value_assignments(
    instructions: tuple[Operation, ...], facts: frozenset[Fact]
) -> Iterable[Fact]:
    operations = {
        operation.offset: operation
        for operation in translate_operations(instructions)
    }
    stores = {
        "fistp": "integer",
        "fistp32": "long",
        "fstp": "float",
        "fstp64": "double",
    }
    for value in facts:
        if (
            value.kind != "reference.array_value"
            or len(value.subject) != 2
            or len(value.value) != 2
        ):
            continue
        terminal = operations.get(value.subject[1])
        target_kind = stores.get(terminal.kind) if terminal is not None else None
        if (
            terminal is None
            or target_kind != value.value[1]
            or len(terminal.args) != 1
        ):
            continue
        target = resolve_slot(terminal.args[0], facts) or resolve_array_element(
            terminal.args[0], facts
        )
        if target is None:
            continue
        yield Fact(
            "semantic.assign",
            (value.subject[0], terminal.end),
            (target.value, value.value[0]),
            combine_evidence(value.evidence, target.evidence, (terminal.offset,)),
            "anchored",
        )


def _computed_array_assignments(
    instructions: tuple[Operation, ...], facts: frozenset[Fact]
) -> Iterable[Fact]:
    by_end = {instruction.end: instruction for instruction in instructions}
    instruction_ends = {
        instruction.offset: instruction.end for instruction in instructions
    }
    expressions: dict[int, list[Fact]] = {}
    for fact in facts:
        if fact.kind not in {"expression.value", "register.value"} or not fact.evidence:
            continue
        if fact.kind == "register.value" and fact.subject[1:] != ("ax",):
            continue
        end = instruction_ends.get(fact.evidence[-1])
        if end is not None:
            expressions.setdefault(end, []).append(fact)
    for target in facts:
        if (
            target.kind != "reference.array_store"
            or len(target.subject) != 2
            or len(target.value) != 2
        ):
            continue
        source = None
        source_start = None
        candidates = expressions.get(target.subject[0], ())
        if len(candidates) == 1:
            expression = candidates[0]
            source = resolve_expression(expression.value[0], facts)
            source_start = expression.evidence[0]
        if source is None and target.value[1] == "string":
            read = by_end.get(target.subject[0])
            setup = by_end.get(read.offset) if read is not None else None
            if (
                setup is not None
                and read is not None
                and setup.kind == "x86.mov_imm"
                and setup.operands[:1] == ("si",)
                and len(setup.operands) == 2
                and read.kind == "tb.runtime"
                and read.operands == (0x9C,)
            ):
                source = resolve_expression(
                    ("memory", setup.operands[1], "string"), facts
                )
                source_start = setup.offset
        if source is None or not isinstance(source_start, int):
            continue
        yield Fact(
            "semantic.assign",
            (source_start, target.subject[1]),
            (target.value[0], source.value),
            combine_evidence(target.evidence, source.evidence, (source_start,)),
            "anchored",
        )


def _assignment(
    effect: Fact,
    facts: frozenset[Fact],
    instructions: dict[int, Operation],
    instruction_ends: dict[int, int],
    targets: dict[object, Resolved | None],
    values: dict[tuple[object, ...], Resolved | None],
) -> Fact | None:
    address = effect.subject[0] if effect.subject else None
    if address not in targets:
        targets[address] = resolve_slot(address, facts) or resolve_array_element(
            address, facts
        )
    target = targets[address]
    if target is None:
        return None
    value_key = effect.kind, effect.value, target.value, effect.evidence
    if value_key not in values:
        direct = (
            resolve_expression_before(
                effect.evidence[-1],
                facts,
                instruction_ends,
            )
            if effect.kind == "machine.store"
            and effect.value == (("register", "ax"),)
            and effect.evidence
            else None
        )
        values[value_key] = direct or _effect_value(effect, target.value, facts)
    value = values[value_key]
    if value is None:
        return None
    support = combine_evidence(effect.evidence, target.evidence, value.evidence)
    end = _effect_end(effect, instructions)
    if end is None:
        return None
    return Fact(
        "semantic.assign",
        (effect.evidence[0], end),
        (target.value, value.value),
        support,
        "anchored",
    )


def _effect_end(effect: Fact, instructions: dict[int, Operation]) -> int | None:
    last = instructions.get(effect.evidence[-1]) if effect.evidence else None
    return last.end if last is not None else None


def _effect_value(
    effect: Fact, target: object, facts: frozenset[Fact]
) -> Resolved | None:
    if effect.kind == "machine.store":
        if effect.value == (("register", "ax"),) and effect.evidence:
            matches = [
                fact
                for fact in facts
                if fact.kind == "reference.array_value"
                and fact.subject[1:] == (effect.evidence[-1],)
            ]
            if len(matches) == 1:
                return Resolved(matches[0].value[0], matches[0].evidence)
        return resolve_expression(effect.value[0], facts)
    operator, operand = effect.value
    right = resolve_expression(operand, facts)
    if right is None:
        return None
    return Resolved(("binary", operator, target, right.value), right.evidence)


ASSIGNMENT_FACT_PASSES: tuple[NamedPass, ...] = (
    ("assignments", assignment_facts),
)
