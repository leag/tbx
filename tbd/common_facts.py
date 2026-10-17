from __future__ import annotations

import struct
from collections.abc import Iterable
from itertools import count, islice

from tbd.canonical import _RESERVED, _letters
from tbd.facts import Evidence, NamedPass, fact_key, reads
from tbd.ir import Fact
from tbd.pool_facts import instruction_memory_accesses
from tbd.semantic import combine_evidence

_COMMON_BASE = 0x110
_ARRAY_BLOCK = 0x36
_WIDTHS = {"integer": 2, "long": 4, "float": 4, "double": 8, "string": 4}
_SUFFIXES = {"integer": "%", "long": "&", "double": "#", "string": "$"}


@reads("layout.runtime_grid", "tb.fp", "x86.mov_acc_mem")
def common_band_facts(evidence: Evidence, facts: frozenset[Fact]) -> Iterable[Fact]:
    """Recover COMMON declarations from the shared-data layout."""

    stamped = _common_stamp(evidence.image)
    typed = _typed_evidence(evidence)
    slots = _stamped_slots(stamped, typed) if stamped is not None else ()
    if not slots:
        slots = _runtime_common_slots(facts, typed)
    if stamped is None and not any(
        fact.kind == "layout.runtime_grid" and fact.value[3] is True for fact in facts
    ):
        return
    summary = stamped[1:] if stamped is not None else (0, 0, 0)
    yield Fact(
        "layout.common_band",
        ("program",),
        summary,
        combine_evidence(*(support for _address, _kind, support in slots)),
        "anchored",
    )
    for order, (address, kind, support) in enumerate(slots):
        yield Fact(
            "layout.common_slot",
            (address,),
            (order, kind, _WIDTHS[kind]),
            support,
            "anchored",
        )


@reads(
    "layout.common_band",
    "layout.common_slot",
    "layout.runtime_array",
    "semantic.dynamic_dim",
)
def common_statement_facts(
    evidence: Evidence, facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Convert COMMON layout facts into source-level statements."""

    scalar_facts = sorted(
        (fact for fact in facts if fact.kind == "layout.common_slot"),
        key=lambda fact: (fact.value[0], fact_key(fact)),
    )
    arrays = sorted(
        (
            fact
            for fact in facts
            if fact.kind == "layout.runtime_array" and fact.value[-1] is True
        ),
        key=lambda fact: (fact.value[0], fact_key(fact)),
    )
    if not any(fact.kind == "layout.common_band" for fact in facts):
        return
    if not scalar_facts and not arrays:
        return
    array_names = tuple(f"{fact.value[1]}({fact.value[3]})" for fact in arrays)
    scalar_names = tuple(
        _scalar_name(fact.value[0], fact.value[1]) for fact in scalar_facts
    )
    dynamic_dims = [fact for fact in facts if fact.kind == "semantic.dynamic_dim"]
    address = (
        max(fact.subject[1] for fact in dynamic_dims)
        if arrays and dynamic_dims
        else evidence.instructions[0].offset
    )
    support = combine_evidence(*(fact.evidence for fact in (*arrays, *scalar_facts)))
    yield Fact(
        "semantic.common",
        (address, 0),
        (array_names + scalar_names,),
        support,
        "anchored",
    )


def _common_stamp(image: bytes) -> tuple[int, int, int, int] | None:
    matches = []
    for offset in range(16, len(image) - 16, 2):
        s1, b1, s2, b2, count, grid, zero, last = struct.unpack_from(
            "<8H", image, offset
        )
        if (
            count == zero == 0
            and b1 == grid == last == _COMMON_BASE
            and b2 == b1 + s1
            and (s1 or s2)
            and s1 % 2 == 0
            and s2 % 4 == 0
            and s1 < 0x1000
            and s2 < 0x1000
        ):
            matches.append((offset, b1, s1, s2))
    return matches[0] if len(matches) == 1 else None


def _stamped_slots(
    stamp: tuple[int, int, int, int],
    typed: dict[int, tuple[str, tuple[int, ...]]],
) -> tuple[tuple[int, str, tuple[int, ...]], ...]:
    stamp_address, base, numeric_size, string_size = stamp
    slots = []
    address = base
    numeric_end = base + numeric_size
    while address < numeric_end:
        kind, support = typed.get(address, ("integer", ()))
        if kind == "string" or address + _WIDTHS[kind] > numeric_end:
            return ()
        slots.append((address, kind, combine_evidence(support, (stamp_address,))))
        address += _WIDTHS[kind]
    for address in range(numeric_end, numeric_end + string_size, 4):
        support = typed.get(address, ("string", ()))[1]
        slots.append((address, "string", combine_evidence(support, (stamp_address,))))
    return tuple(slots)


def _runtime_common_slots(
    facts: frozenset[Fact],
    typed: dict[int, tuple[str, tuple[int, ...]]],
) -> tuple[tuple[int, str, tuple[int, ...]], ...]:
    grids = [
        fact
        for fact in facts
        if fact.kind == "layout.runtime_grid" and fact.value[3] is True
    ]
    if len(grids) != 1:
        return ()
    blocks, n_static, scalar_base, _common, _ds = grids[0].value
    if not blocks:
        return ()
    start = blocks[-1] + _ARRAY_BLOCK
    static_base = scalar_base - _ARRAY_BLOCK * n_static
    addresses = sorted(address for address in typed if start <= address < static_base)
    return tuple(
        (
            address,
            typed[address][0],
            combine_evidence(typed[address][1], grids[0].evidence),
        )
        for address in addresses
    )


def _typed_evidence(
    evidence: Evidence,
) -> dict[int, tuple[str, tuple[int, ...]]]:
    grouped: dict[int, tuple[set[str], set[int]]] = {}
    for instruction in evidence.instructions:
        for _action, address, kind in instruction_memory_accesses(instruction):
            if kind not in _WIDTHS:
                continue
            kinds, support = grouped.setdefault(address, (set(), set()))
            kinds.add(kind)
            support.add(instruction.offset)
    return {
        address: (next(iter(kinds)), tuple(sorted(support)))
        for address, (kinds, support) in grouped.items()
        if len(kinds) == 1
    }


def _scalar_name(order: int, kind: str) -> str:
    """Name the ``order``-th COMMON variable as the program's names do.

    The program names its variables A, B, ... skipping BASIC's reserved
    words, COMMON variables first, so the declaration must skip them too.
    """
    names = (name for index in count() if (name := _letters(index)) not in _RESERVED)
    return next(islice(names, order, None)) + _SUFFIXES.get(kind, "")


COMMON_LAYOUT_PASSES: tuple[NamedPass, ...] = (("common-band", common_band_facts),)

COMMON_STATEMENT_PASSES: tuple[NamedPass, ...] = (
    ("common-statement", common_statement_facts),
)
