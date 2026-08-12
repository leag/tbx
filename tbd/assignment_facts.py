"""Source-shaped assignment facts resolved from additive machine facts."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from tbd.facts import Evidence, NamedPass
from tbd.ir import Fact


@dataclass(frozen=True)
class _Resolved:
    value: object
    evidence: tuple[int, ...] = ()


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
    target = _resolve_target(address, facts)
    if target is None:
        return None
    value = _effect_value(effect, target.value, facts)
    if value is None:
        return None
    evidence = _evidence(effect.evidence, target.evidence, value.evidence)
    return Fact(
        "semantic.assign",
        (effect.evidence[0],),
        (target.value, value.value),
        evidence,
        "anchored",
    )


def _effect_value(
    effect: Fact, target: object, facts: frozenset[Fact]
) -> _Resolved | None:
    if effect.kind == "machine.store":
        return _resolve(effect.value[0], facts)
    operator, operand = effect.value
    right = _resolve(operand, facts)
    if right is None:
        return None
    return _Resolved(("binary", operator, target, right.value), right.evidence)


def _resolve(value: Any, facts: frozenset[Fact]) -> _Resolved | None:
    if not isinstance(value, tuple):
        return _Resolved(value)
    if value and value[0] == "memory":
        return _resolve_memory(value, facts)
    if value and value[0] == "binary" and len(value) == 4:
        return _resolve_binary(value, facts)
    if value and value[0] in {"const", "string"}:
        return _Resolved(value)
    return None


def _resolve_binary(value: tuple[Any, ...], facts: frozenset[Fact]) -> _Resolved | None:
    left = _resolve(value[2], facts)
    right = _resolve(value[3], facts)
    if left is None or right is None:
        return None
    expression = "binary", value[1], left.value, right.value
    return _Resolved(expression, _evidence(left.evidence, right.evidence))


def _resolve_memory(value: tuple[Any, ...], facts: frozenset[Fact]) -> _Resolved | None:
    if len(value) < 2 or not isinstance(value[1], int):
        return None
    address = value[1]
    if constant := _unique(facts, "constant", ("memory", address)):
        return _Resolved(constant.value, constant.evidence)
    target = _resolve_target(address, facts)
    if target is None:
        return None
    suffix = value[2:] if len(value) > 2 else ()
    return _Resolved(target.value + suffix, target.evidence)


def _resolve_target(address: object, facts: frozenset[Fact]) -> _Resolved | None:
    if not isinstance(address, int):
        return None
    slot = _unique(facts, "slot", (address,))
    if slot is None:
        return None
    name = slot.value[0]
    return _Resolved(("slot", name, address), slot.evidence)


def _unique(facts: frozenset[Fact], kind: str, subject: tuple[object, ...]) -> Fact | None:
    matches = [fact for fact in facts if fact.kind == kind and fact.subject == subject]
    return matches[0] if len(matches) == 1 else None


def _evidence(*groups: tuple[int, ...]) -> tuple[int, ...]:
    return tuple(sorted({address for group in groups for address in group}))


ASSIGNMENT_FACT_PASSES: tuple[NamedPass, ...] = (
    ("assignments", assignment_facts),
)
