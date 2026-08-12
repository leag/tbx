"""Shared resolution of address-based facts into semantic expressions."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from tbd.ir import Fact


@dataclass(frozen=True)
class Resolved:
    value: object
    evidence: tuple[int, ...] = ()


def resolve_expression(value: Any, facts: frozenset[Fact]) -> Resolved | None:
    if not isinstance(value, tuple):
        return Resolved(value)
    if value and value[0] == "memory":
        return _resolve_memory(value, facts)
    if value and value[0] == "binary" and len(value) == 4:
        return _resolve_binary(value, facts)
    if value and value[0] in {"const", "string"}:
        return Resolved(value)
    return None


def resolve_slot(address: object, facts: frozenset[Fact]) -> Resolved | None:
    if not isinstance(address, int):
        return None
    slot = unique_fact(facts, "slot", (address,))
    if slot is None:
        return None
    return Resolved(("slot", slot.value[0], address), slot.evidence)


def resolve_string(address: object, facts: frozenset[Fact]) -> Resolved | None:
    if not isinstance(address, int):
        return None
    constant = unique_fact(facts, "constant", ("string", address))
    return Resolved(constant.value, constant.evidence) if constant else None


def unique_fact(
    facts: frozenset[Fact], kind: str, subject: tuple[object, ...]
) -> Fact | None:
    matches = [fact for fact in facts if fact.kind == kind and fact.subject == subject]
    return matches[0] if len(matches) == 1 else None


def combine_evidence(*groups: tuple[int, ...]) -> tuple[int, ...]:
    return tuple(sorted({address for group in groups for address in group}))


def _resolve_binary(value: tuple[Any, ...], facts: frozenset[Fact]) -> Resolved | None:
    left = resolve_expression(value[2], facts)
    right = resolve_expression(value[3], facts)
    if left is None or right is None:
        return None
    expression = "binary", value[1], left.value, right.value
    return Resolved(expression, combine_evidence(left.evidence, right.evidence))


def _resolve_memory(value: tuple[Any, ...], facts: frozenset[Fact]) -> Resolved | None:
    if len(value) < 2 or not isinstance(value[1], int):
        return None
    address = value[1]
    constant = unique_fact(facts, "constant", ("memory", address))
    slot = resolve_slot(address, facts)
    if constant is not None and slot is not None:
        return None
    if constant is not None:
        return Resolved(constant.value, constant.evidence)
    if slot is None:
        return None
    suffix = value[2:] if len(value) > 2 else ()
    return Resolved(slot.value + suffix, slot.evidence)
