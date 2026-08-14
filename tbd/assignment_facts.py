"""Source-shaped assignment facts resolved from additive machine facts."""

from __future__ import annotations

from collections.abc import Iterable

from tbd.facts import Evidence, NamedPass
from tbd.ir import Fact, Operation
from tbd.semantic import (
    Resolved,
    combine_evidence,
    resolve_array_element,
    resolve_expression,
    resolve_slot,
)


def assignment_facts(
    evidence: Evidence, facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Resolve complete stores and updates into source-shaped assignments."""

    instructions = {
        instruction.offset: instruction for instruction in evidence.instructions
    }
    targets: dict[object, Resolved | None] = {}
    values: dict[tuple[object, ...], Resolved | None] = {}
    for effect in facts:
        if effect.kind not in {"machine.store", "machine.update"}:
            continue
        assignment = _assignment(
            effect, facts, instructions, targets, values
        )
        if assignment is not None:
            yield assignment


def _assignment(
    effect: Fact,
    facts: frozenset[Fact],
    instructions: dict[int, Operation],
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
    value_key = effect.kind, effect.value, target.value
    if value_key not in values:
        values[value_key] = _effect_value(effect, target.value, facts)
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
        return resolve_expression(effect.value[0], facts)
    operator, operand = effect.value
    right = resolve_expression(operand, facts)
    if right is None:
        return None
    return Resolved(("binary", operator, target, right.value), right.evidence)


ASSIGNMENT_FACT_PASSES: tuple[NamedPass, ...] = (
    ("assignments", assignment_facts),
)
