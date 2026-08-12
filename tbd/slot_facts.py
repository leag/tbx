"""DGROUP slot facts derived from memory roles and an anchored pool boundary."""

from __future__ import annotations

from collections.abc import Iterable

from tbd.facts import Evidence, NamedPass
from tbd.ir import Fact, Slot
from tbd.slots import VAR_BASE, is_slot, slot_name


def slot_facts(
    _evidence: Evidence, facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Name supported scalar cells below one unambiguous pool boundary."""

    layouts = [fact for fact in facts if fact.kind == "layout.pool"]
    if len(layouts) != 1:
        return
    layout = layouts[0]
    pool_base, marker = layout.value[1], layout.value[2]
    accesses = _slot_accesses(facts, pool_base)
    for address, related in sorted(accesses.items()):
        types = tuple(sorted({fact.value[0] for fact in related}))
        evidence = tuple(
            sorted({marker, *(source for fact in related for source in fact.evidence)})
        )
        yield Fact(
            "slot",
            (address,),
            (slot_name(address), types),
            evidence,
            "anchored",
        )


def _slot_accesses(
    facts: frozenset[Fact], pool_base: object
) -> dict[int, list[Fact]]:
    if not isinstance(pool_base, int):
        return {}
    found: dict[int, list[Fact]] = {}
    for fact in facts:
        if not _is_slot_access(fact, pool_base):
            continue
        address = fact.subject[0]
        found.setdefault(address, []).append(fact)
    return found


def _is_slot_access(fact: Fact, pool_base: int) -> bool:
    if fact.kind not in {"memory.read", "memory.write"} or not fact.subject:
        return False
    address = fact.subject[0]
    return (
        isinstance(address, int)
        and VAR_BASE <= address < pool_base - 4
        and is_slot(address)
        and bool(fact.value)
        and isinstance(fact.value[0], str)
    )


def materialize_slots(facts: tuple[Fact, ...]) -> tuple[Slot, ...]:
    """Build the canonical slot view from additive slot conclusions."""

    found: dict[int, tuple[set[str], set[str]]] = {}
    for fact in facts:
        if not _valid_slot_fact(fact):
            continue
        address = fact.subject[0]
        names, types = found.setdefault(address, (set(), set()))
        names.add(fact.value[0])
        types.update(fact.value[1])
    return tuple(
        Slot(
            address,
            next(iter(names)) if len(names) == 1 else slot_name(address),
            tuple(sorted(types)),
        )
        for address, (names, types) in sorted(found.items())
    )


def _valid_slot_fact(fact: Fact) -> bool:
    return (
        fact.kind == "slot"
        and len(fact.subject) == 1
        and isinstance(fact.subject[0], int)
        and len(fact.value) == 2
        and isinstance(fact.value[0], str)
        and isinstance(fact.value[1], tuple)
        and all(isinstance(item, str) for item in fact.value[1])
    )


SLOT_FACT_PASSES: tuple[NamedPass, ...] = (("dgroup-slots", slot_facts),)
