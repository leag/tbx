"""COLOR facts over the compiler's complete optional-cell scaffold."""

from __future__ import annotations

import struct
from collections.abc import Iterable
from dataclasses import dataclass

from tbd.facts import Evidence, NamedPass
from tbd.ir import Fact, Operation
from tbd.matchers import fp_ax_bridge
from tbd.semantic import combine_evidence, resolve_expression

_COLOR_CELLS = ((0x04, 0x88), (0x02, 0x94), (0x01, 0xA0))


@dataclass(frozen=True)
class ColorMatch:
    """One exact COLOR cell-staging chain and commit signature."""

    start: int
    end: int
    operands: tuple[object | None, ...]
    evidence: tuple[int, ...]


def color_statement_facts(
    evidence: Evidence, facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Resolve complete canonical COLOR scaffolds into source-shaped facts."""

    by_end = {instruction.end: instruction for instruction in evidence.instructions}
    for instruction in evidence.instructions:
        match = _color_match(instruction, by_end, facts)
        if match is None:
            continue
        yield Fact(
            "semantic.color",
            (match.start, match.end),
            match.operands,
            match.evidence,
            "anchored",
        )


def _color_match(
    instruction: Operation,
    by_end: dict[int, Operation],
    facts: frozenset[Fact],
) -> ColorMatch | None:
    if (
        instruction.kind != "tb.statement"
        or len(instruction.operands) != 3
        or instruction.operands[:2] != ("COLOR", 0x22)
        or not isinstance(instruction.operands[2], int)
    ):
        return None
    mask = instruction.operands[2]
    if mask == 0 or mask & ~0x07:
        return None
    cursor = instruction.offset
    operands: list[object | None] = [None, None, None]
    support: tuple[int, ...] = (instruction.offset,)
    for index, (bit, address) in reversed(tuple(enumerate(_COLOR_CELLS))):
        if not mask & bit:
            continue
        resolved = _color_store(by_end.get(cursor), address, by_end, facts)
        if resolved is None:
            return None
        value, start, value_evidence = resolved
        operands[index] = value
        cursor = start
        support = combine_evidence(support, value_evidence)
    return ColorMatch(cursor, instruction.end, tuple(operands), support)


def _color_store(
    store: Operation | None,
    address: int,
    by_end: dict[int, Operation],
    facts: frozenset[Fact],
) -> tuple[object, int, tuple[int, ...]] | None:
    if store is None:
        return None
    raw = bytes.fromhex(store.raw)
    if len(raw) == 6 and raw[:2] == b"\xc7\x06":
        actual, value = struct.unpack_from("<HH", raw, 2)
        if actual != address:
            return None
        return ("const", value), store.offset, (store.offset,)
    if len(raw) != 4 or raw[:2] != b"\x89\x06":
        return None
    if struct.unpack_from("<H", raw, 2)[0] != address:
        return None
    bridge = fp_ax_bridge(by_end.get(store.offset), by_end)
    if bridge is None:
        return None
    expression, bridge_evidence = bridge
    resolved = resolve_expression(expression, facts)
    if resolved is None:
        return None
    return (
        resolved.value,
        bridge_evidence[0],
        combine_evidence(bridge_evidence, resolved.evidence, (store.offset,)),
    )


COLOR_FACT_PASSES: tuple[NamedPass, ...] = (("color", color_statement_facts),)
