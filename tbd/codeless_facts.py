from __future__ import annotations

import struct
from collections.abc import Iterable

from tbd.facts import Evidence, NamedPass, reads
from tbd.ir import Fact, Operation
from tbd.semantic import combine_evidence


@reads("semantic.", "tb.epilogue", "tb.prologue", "tb.statement")
def line_table_facts(evidence: Evidence, facts: frozenset[Fact]) -> Iterable[Fact]:
    """Recover declarations encoded in Turbo Basic line tables."""

    prologues = [
        instruction
        for instruction in evidence.instructions
        if instruction.kind == "tb.prologue"
    ]
    epilogues = [
        instruction
        for instruction in evidence.instructions
        if instruction.kind == "tb.epilogue"
    ]
    error_sites = _active_error_sites(evidence.instructions)
    if len(prologues) != 1 or len(epilogues) != 1 or not error_sites:
        return
    start, epilogue = prologues[0].offset, epilogues[0]
    first_offset = prologues[0].end - start
    valid_offsets = _statement_offsets(evidence, facts, start, epilogue.offset)
    matches = _line_table_candidates(
        evidence.image,
        epilogue,
        start,
        first_offset,
        valid_offsets,
    )
    if matches:
        longest = max(len(match[3]) for match in matches)
        matches = [match for match in matches if len(match[3]) == longest]
    if len(matches) != 1:
        return
    table_offset, entries, orphans, records = matches[0]
    yield Fact(
        "layout.line_table",
        (table_offset, epilogue.offset),
        (entries, orphans),
        combine_evidence(error_sites, (epilogue.offset,), records),
        "anchored",
    )


@reads(
    "layout.array",
    "layout.common_band",
    "layout.data_items",
    "layout.line_table",
    "layout.pool",
    "layout.runtime_array",
    "option.base",
    "semantic.common",
    "semantic.data",
    "semantic.dim",
    "semantic.do_codeless",
    "semantic.dynamic_dim",
    "semantic.local_dim",
    "semantic.option_base",
)
def def_type_facts(_evidence: Evidence, facts: frozenset[Fact]) -> Iterable[Fact]:
    """Recover DEF-type declarations from codeless program evidence."""

    if _has_competing_codeless_evidence(facts):
        return
    has_pool = any(fact.kind == "layout.pool" for fact in facts)
    data = [fact for fact in facts if fact.kind == "layout.data_items"]
    statements = [fact for fact in facts if fact.kind == "semantic.data"]
    if has_pool and not data:
        return
    if data and not statements:
        return
    tables = [fact for fact in facts if fact.kind == "layout.line_table"]
    if len(tables) != 1 or len(tables[0].value) != 2:
        return
    orphans = tables[0].value[1]
    claimed = {
        statement.subject[:2] for statement in statements if len(statement.subject) >= 2
    }
    for order, orphan in enumerate(orphans):
        if (
            not isinstance(orphan, tuple)
            or len(orphan) != 3
            or not isinstance(orphan[0], int)
            or not isinstance(orphan[2], int)
        ):
            return
        address, _line, record = orphan
        if (address, order) in claimed:
            continue
        yield Fact(
            "semantic.def_type",
            (address, order),
            ("SNG", "A", "Z"),
            combine_evidence((record,), tables[0].evidence),
            "anchored",
        )


def _active_error_sites(instructions: tuple[Operation, ...]) -> tuple[int, ...]:
    return tuple(
        instruction.offset
        for instruction in instructions
        if _active_error_instruction(instruction)
    )


def _active_error_instruction(instruction: Operation) -> bool:
    return (
        instruction.kind == "tb.statement"
        and instruction.operands[:1]
        in {
            ("ON_ERROR",),
            ("RESUME_BEGIN",),
            ("ERROR",),
        }
    ) or instruction.raw in {"8b 06 72 00", "8b 06 74 00"}


def _statement_offsets(
    evidence: Evidence,
    facts: frozenset[Fact],
    start: int,
    epilogue: int,
) -> set[int]:
    addresses = {
        block.start for block in evidence.blocks if start < block.start < epilogue
    }
    addresses.update(
        fact.subject[0]
        for fact in facts
        if fact.kind.startswith("semantic.")
        and fact.subject
        and isinstance(fact.subject[0], int)
        and start < fact.subject[0] < epilogue
    )
    return {address - start for address in addresses}


def _line_table_candidates(
    image: bytes,
    epilogue: Operation,
    start: int,
    first_offset: int,
    valid_offsets: set[int],
) -> list[
    tuple[
        int,
        tuple[tuple[int, int, int], ...],
        tuple[tuple[int, int, int], ...],
        tuple[int, ...],
    ]
]:
    marker = struct.pack("<H", first_offset)
    terminal = epilogue.offset - start
    candidates = []
    cursor = epilogue.offset
    while True:
        cursor = image.find(marker, cursor + 1)
        if cursor < 0:
            break
        parsed = _parse_line_table(image, cursor, start, terminal, valid_offsets)
        if parsed is not None:
            entries, orphans, records = parsed
            candidates.append((cursor, entries, orphans, records))
    return candidates


def _parse_line_table(
    image: bytes,
    table_offset: int,
    start: int,
    terminal: int,
    valid_offsets: set[int],
) -> (
    tuple[
        tuple[tuple[int, int, int], ...],
        tuple[tuple[int, int, int], ...],
        tuple[int, ...],
    ]
    | None
):
    entries: dict[int, tuple[int, int]] = {}
    orphans: list[tuple[int, int, int]] = []
    records = []
    cursor, previous_offset, previous_line = table_offset, 0, 0
    while cursor + 4 <= len(image):
        offset, line = struct.unpack_from("<HH", image, cursor)
        records.append(cursor)
        if offset == terminal:
            if line != previous_line or not entries:
                return None
            materialized = tuple(
                (start + offset, value[0], value[1])
                for offset, value in entries.items()
            )
            return materialized, tuple(orphans), tuple(records)
        if (
            offset not in valid_offsets
            or offset < previous_offset
            or line < previous_line
        ):
            return None
        if offset in entries:
            previous = entries[offset]
            orphans.append((start + offset, previous[0], previous[1]))
        entries[offset] = (line, cursor)
        previous_offset, previous_line = offset, line
        cursor += 4
    return None


def _has_competing_codeless_evidence(facts: frozenset[Fact]) -> bool:
    competing = {
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
    return any(fact.kind in competing for fact in facts)


CODELESS_FACT_PASSES: tuple[NamedPass, ...] = (
    ("line-table", line_table_facts),
    ("codeless-def-type", def_type_facts),
)
