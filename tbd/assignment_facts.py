"""Source-shaped assignment facts resolved from additive machine facts."""

from __future__ import annotations

from collections.abc import Iterable

from tbd.facts import Evidence, NamedPass
from tbd.ir import Fact
from tbd.semantic import Resolved, combine_evidence, resolve_expression, resolve_slot


def assignment_facts(
    _evidence: Evidence, facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Resolve complete stores and updates into source-shaped assignments."""

    for effect in facts:
        if effect.kind not in {"machine.store", "machine.update"}:
            continue
        assignment = _assignment(effect, facts)
        if assignment is not None:
            yield assignment


def _assignment(effect: Fact, facts: frozenset[Fact]) -> Fact | None:
    address = effect.subject[0] if effect.subject else None
    target = resolve_slot(address, facts)
    if target is None:
        return None
    value = _effect_value(effect, target.value, facts)
    if value is None:
        return None
    evidence = combine_evidence(effect.evidence, target.evidence, value.evidence)
    return Fact(
        "semantic.assign",
        (effect.evidence[0],),
        (target.value, value.value),
        evidence,
        "anchored",
    )


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
