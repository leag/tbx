"""SCREEN facts over the compiler's complete optional-cell scaffold."""

from __future__ import annotations

import struct
from collections.abc import Iterable
from dataclasses import dataclass

from tbd.facts import Evidence, NamedPass
from tbd.ir import Fact, Operation

_SCREEN_CELLS = ((0x08, 0x88), (0x04, 0x94), (0x02, 0xA0), (0x01, 0xAC))


@dataclass(frozen=True)
class ScreenMatch:
    """One exact immediate SCREEN cell-staging chain and commit signature."""

    start: int
    end: int
    operands: tuple[object | None, ...]
    evidence: tuple[int, ...]


def screen_statement_facts(
    evidence: Evidence, _facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Resolve complete calibrated SCREEN scaffolds into source-shaped facts."""

    by_end = {instruction.end: instruction for instruction in evidence.instructions}
    for instruction in evidence.instructions:
        match = _screen_match(instruction, by_end)
        if match is None:
            continue
        yield Fact(
            "semantic.screen",
            (match.start, match.end),
            match.operands,
            match.evidence,
            "anchored",
        )


def _screen_match(
    instruction: Operation, by_end: dict[int, Operation]
) -> ScreenMatch | None:
    mask = _screen_mask(instruction)
    if mask is None:
        return None
    resolved = _screen_operands(mask, instruction.offset, by_end)
    if resolved is None:
        return None
    cursor, operands, support = resolved
    return ScreenMatch(cursor, instruction.end, operands, support)


def _screen_mask(instruction: Operation) -> int | None:
    if instruction.kind != "tb.statement" or len(instruction.operands) != 3:
        return None
    if instruction.operands[:2] != ("SCREEN", 0xC6):
        return None
    mask = instruction.operands[2]
    if not isinstance(mask, int) or mask == 0 or mask & ~0x0F:
        return None
    return mask


def _screen_operands(
    mask: int, cursor: int, by_end: dict[int, Operation]
) -> tuple[int, tuple[object | None, ...], tuple[int, ...]] | None:
    operands: list[object | None] = [None, None, None, None]
    support = [cursor]
    for index, (bit, address) in reversed(tuple(enumerate(_SCREEN_CELLS))):
        if not mask & bit:
            continue
        store = by_end.get(cursor)
        value = _immediate_cell_store(store, address)
        if store is None or value is None:
            return None
        operands[index] = ("const", value)
        cursor = store.offset
        support.append(store.offset)
    return cursor, tuple(operands), tuple(sorted(support))


def _immediate_cell_store(store: Operation | None, address: int) -> int | None:
    if store is None:
        return None
    raw = bytes.fromhex(store.raw)
    if len(raw) != 6 or raw[:2] != b"\xc7\x06":
        return None
    actual, value = struct.unpack_from("<HH", raw, 2)
    return value if actual == address else None


SCREEN_FACT_PASSES: tuple[NamedPass, ...] = (("screen", screen_statement_facts),)
