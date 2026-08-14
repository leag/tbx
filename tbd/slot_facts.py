"""DGROUP slot facts derived from memory roles and an anchored pool boundary."""

from __future__ import annotations

from collections.abc import Iterable

from tbd.facts import Evidence, NamedPass
from tbd.ir import Fact, Slot
from tbd.semantic import resolve_array_element
from tbd.slots import VAR_BASE, slot_name

_TYPE_WIDTHS = {
    "integer": 2,
    "long": 4,
    "float": 4,
    "double": 8,
    "string": 4,
}


def slot_facts(
    _evidence: Evidence, facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Name supported scalar cells below one unambiguous pool boundary."""

    layouts = [fact for fact in facts if fact.kind == "layout.pool"]
    if len(layouts) != 1:
        return
    layout = layouts[0]
    pool_base, marker = layout.value[1], layout.value[2]
    array_count = len([fact for fact in facts if fact.kind == "layout.array"])
    scalar_base = VAR_BASE + 0x36 * array_count
    accesses = _slot_accesses(facts, pool_base, scalar_base)
    for address, related in sorted(accesses.items()):
        types = tuple(sorted({fact.value[0] for fact in related}))
        evidence = tuple(
            sorted({marker, *(source for fact in related for source in fact.evidence)})
        )
        yield Fact(
            "slot",
            (address,),
            (_scalar_name(address, scalar_base), types),
            evidence,
            "anchored",
        )


def _slot_accesses(
    facts: frozenset[Fact], pool_base: object, scalar_base: int
) -> dict[int, list[Fact]]:
    if not isinstance(pool_base, int):
        return {}
    constants = {
        fact.subject[1]
        for fact in facts
        if fact.kind == "constant"
        and len(fact.subject) == 2
        and fact.subject[0] in {"memory", "string"}
        and isinstance(fact.subject[1], int)
    }
    found: dict[int, list[Fact]] = {}
    for fact in facts:
        if not _is_slot_access(fact, pool_base, scalar_base):
            continue
        address = fact.subject[0]
        if address in constants:
            continue
        if resolve_array_element(address, facts) is not None:
            continue
        found.setdefault(address, []).append(fact)
    return found


def _is_slot_access(fact: Fact, pool_base: int, scalar_base: int) -> bool:
    if fact.kind not in {"memory.read", "memory.write"} or not fact.subject:
        return False
    address = fact.subject[0]
    kind = fact.value[0] if fact.value else None
    width = _TYPE_WIDTHS.get(kind) if isinstance(kind, str) else None
    return (
        isinstance(address, int)
        and isinstance(width, int)
        and scalar_base <= address
        and address + width <= pool_base
        and (address - scalar_base) % 2 == 0
    )


def _scalar_name(address: int, scalar_base: int) -> str:
    index = (address - scalar_base) // 4 + 1
    half = "H" if (address - scalar_base) % 4 else ""
    return f"V{index:04d}{half}"


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
