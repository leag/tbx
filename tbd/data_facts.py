"""DATA pool ownership and codeless source-statement facts."""

from __future__ import annotations

import struct
from collections.abc import Iterable

from tbd.facts import Evidence, NamedPass
from tbd.ir import Fact
from tbd.pool import decode_string_descriptors
from tbd.semantic import combine_evidence, unique_fact

DataItem = tuple[str, bool, int]


def data_item_facts(
    evidence: Evidence, facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Recover the unique source-order descriptor-pointer table."""

    layout = unique_fact(facts, "layout.pool", ("dgroup",))
    if layout is None or len(layout.value) != 4:
        return
    ds, pool_base, _marker, string_base = layout.value
    descriptors = decode_string_descriptors(
        evidence.image, ds, pool_base, string_base
    )
    if (
        descriptors is None
        or not descriptors
        or not isinstance(ds, int)
        or not isinstance(string_base, int)
    ):
        return
    by_displacement = dict(descriptors)
    referenced = {
        fact.subject[0]
        for fact in facts
        if fact.kind in {"memory.read", "reference.input_prompt"}
        and fact.subject
        and fact.value == ("string",)
        and isinstance(fact.subject[0], int)
    }
    anchors = tuple(
        displacement
        for displacement, _text in reversed(descriptors)
        if displacement not in referenced
    )
    if not anchors:
        return
    candidates = _pointer_tables(
        evidence.image,
        ds,
        string_base,
        by_displacement,
        anchors,
    )
    if len(candidates) != 1:
        return
    start, pointers = candidates[0]
    items = tuple(
        (by_displacement[pointer], _is_string(by_displacement[pointer]), pointer)
        for pointer in pointers
    )
    support = combine_evidence(
        layout.evidence,
        tuple(ds + start + index * 2 for index in range(len(pointers))),
        tuple(ds + pointer for pointer in pointers),
    )
    yield Fact(
        "layout.data_items",
        (ds + start,),
        (items,),
        support,
        "anchored",
    )


def data_statement_facts(
    evidence: Evidence, facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Group anchored DATA items at codeless line-table positions."""

    data = [fact for fact in facts if fact.kind == "layout.data_items"]
    if len(data) != 1 or len(data[0].value) != 1:
        return
    items = data[0].value[0]
    if not isinstance(items, tuple) or not items or _has_targeted_restore(evidence):
        return
    tables = [fact for fact in facts if fact.kind == "layout.line_table"]
    if len(tables) == 1 and len(tables[0].value) == 2:
        orphans = tables[0].value[1]
        count = min(len(items), len(orphans))
        for order in range(count):
            orphan = orphans[order]
            if not _orphan(orphan):
                return
            selected = items[order : order + 1] if order + 1 < count else items[order:]
            yield _data_statement(data[0], orphan, order, selected)
        return
    if (
        tables
        or _has_line_table_witness(evidence)
        or not _has_data_read(evidence)
        or _has_codeless_declarations(facts)
    ):
        return
    if not evidence.instructions:
        return
    yield Fact(
        "semantic.data",
        (evidence.instructions[0].offset, 0),
        (tuple((item[0], item[1]) for item in items),),
        data[0].evidence,
        "anchored",
    )


def _pointer_tables(
    image: bytes,
    ds: int,
    string_base: int,
    descriptors: dict[int, str],
    anchors: tuple[int, ...],
) -> list[tuple[int, tuple[int, ...]]]:
    candidates = []
    for start in range(0x100, string_base, 0x10):
        pointers = []
        displacement = start
        while displacement + 2 <= string_base:
            position = ds + displacement
            if position < 0 or position + 2 > len(image):
                break
            pointer = struct.unpack_from("<H", image, position)[0]
            if pointer not in descriptors:
                break
            pointers.append(pointer)
            displacement += 2
        found = tuple(pointers)
        if found and _contains_in_order(found, anchors):
            candidates.append((start, found))
    return [
        candidate
        for candidate in candidates
        if not any(
            other[0] < candidate[0]
            and other[0] + 2 * len(other[1])
            >= candidate[0] + 2 * len(candidate[1])
            for other in candidates
        )
    ]


def _contains_in_order(values: tuple[int, ...], anchors: tuple[int, ...]) -> bool:
    pending = iter(anchors)
    wanted = next(pending, None)
    for value in values:
        if value == wanted:
            wanted = next(pending, None)
    return wanted is None


def _is_string(text: str) -> bool:
    try:
        float(text)
    except ValueError:
        return True
    return False


def _has_targeted_restore(evidence: Evidence) -> bool:
    return any(
        instruction.raw.startswith("c7 06 78 00 ")
        and instruction.raw != "c7 06 78 00 00 00"
        for instruction in evidence.instructions
    )


def _has_data_read(evidence: Evidence) -> bool:
    return any(
        instruction.kind == "tb.statement"
        and instruction.operands[:1] in {("DATA_NUMBER",), ("DATA_STRING",)}
        for instruction in evidence.instructions
    )


def _has_line_table_witness(evidence: Evidence) -> bool:
    return any(
        (
            instruction.kind == "tb.statement"
            and instruction.operands[:1]
            in {("ON_ERROR",), ("RESUME_BEGIN",), ("ERROR",)}
        )
        or instruction.raw in {"8b 06 72 00", "8b 06 74 00"}
        for instruction in evidence.instructions
    )


def _has_codeless_declarations(facts: frozenset[Fact]) -> bool:
    kinds = {
        "layout.array",
        "layout.common_band",
        "layout.runtime_array",
        "option.base",
        "semantic.common",
        "semantic.dim",
        "semantic.do_codeless",
        "semantic.dynamic_dim",
        "semantic.local_dim",
        "semantic.option_base",
    }
    return any(fact.kind in kinds for fact in facts)


def _orphan(value: object) -> bool:
    return (
        isinstance(value, tuple)
        and len(value) == 3
        and isinstance(value[0], int)
        and isinstance(value[2], int)
    )


def _data_statement(
    data: Fact,
    orphan: tuple[object, ...],
    order: int,
    items: tuple[DataItem, ...],
) -> Fact:
    address, _line, record = orphan
    assert isinstance(address, int)
    assert isinstance(record, int)
    return Fact(
        "semantic.data",
        (address, order),
        (tuple((item[0], item[1]) for item in items),),
        combine_evidence(data.evidence, (record,)),
        "anchored",
    )


DATA_FACT_PASSES: tuple[NamedPass, ...] = (
    ("data-items", data_item_facts),
    ("data-statements", data_statement_facts),
)
