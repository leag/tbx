from __future__ import annotations

import struct
from collections.abc import Iterable
from dataclasses import dataclass

from tbd.facts import Evidence, NamedPass, reads
from tbd.ir import Fact, Operation
from tbd.matchers import fp_ax_bridge
from tbd.semantic import combine_evidence, resolve_expression

_COLOR_CELLS = ((0x04, 0x88), (0x02, 0x94), (0x01, 0xA0))


@dataclass(frozen=True)
class ColorMatch:
    """Decoded COLOR statement operands and supporting offsets."""

    start: int
    end: int
    operands: tuple[object | None, ...]
    evidence: tuple[int, ...]


@reads(
    "constant",
    "expression.system",
    "layout.array",
    "reference.array_value",
    "slot",
    "tb.fp",
    "tb.fwait",
    "tb.statement",
    "x86.mov_acc_mem",
)
def color_statement_facts(evidence: Evidence, facts: frozenset[Fact]) -> Iterable[Fact]:
    """Recover COLOR statements from their runtime call scaffold."""

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
    load = by_end.get(store.offset)
    load_raw = bytes.fromhex(load.raw) if load is not None else b""
    if len(load_raw) == 4 and load_raw[:2] == b"\x8b\x06":
        # An integer argument is loaded into AX from its variable.
        source = struct.unpack_from("<H", load_raw, 2)[0]
        loaded = resolve_expression(("memory", source, "integer"), facts)
        if loaded is None:
            return None
        return (
            loaded.value,
            load.offset,
            combine_evidence(loaded.evidence, (load.offset, store.offset)),
        )
    bridge = fp_ax_bridge(by_end.get(store.offset), by_end)
    if bridge is None:
        return _element_through_ax(store, by_end, facts)
    expression, bridge_evidence = bridge
    resolved = resolve_expression(expression, facts)
    if resolved is None:
        return None
    return (
        resolved.value,
        bridge_evidence[0],
        combine_evidence(bridge_evidence, resolved.evidence, (store.offset,)),
    )


def _element_through_ax(
    store: Operation, by_end: dict[int, Operation], facts: frozenset[Fact]
) -> tuple[object, int, tuple[int, ...]] | None:
    """Read a numeric array element rounded to an integer through AX.

    ``fld [si]`` of the element, ``fistp [t]; fwait; mov ax,[t]``, then the
    store: ``COLOR V1(I%)`` (``smenu0.exe`` 0xe349).
    """
    reload = by_end.get(store.offset)
    if reload is None or reload.kind != "x86.mov_acc_mem":
        return None
    rounding = by_end.get(reload.offset)
    if rounding is not None and rounding.kind == "tb.fwait":
        rounding = by_end.get(rounding.offset)
    if rounding is None or rounding.kind != "tb.fp":
        return None
    raw = bytes.fromhex(rounding.raw)
    # ``fistp word [t]`` into the temporary AX reloads.
    if (
        len(raw) != 5
        or raw[:3] != b"\xcd\x3b\x1e"
        or reload.operands[:1] != (struct.unpack_from("<H", raw, 3)[0],)
    ):
        return None
    elements = [
        fact
        for fact in facts
        if fact.kind == "reference.array_value"
        and len(fact.subject) == 2
        and fact.subject[1] == rounding.offset
        and fact.value[1:] in {("float",), ("double",), ("integer",)}
    ]
    if len(elements) != 1:
        return None
    element = elements[0]
    return (
        element.value[0],
        element.subject[0],
        combine_evidence(
            element.evidence, (rounding.offset, reload.offset, store.offset)
        ),
    )


COLOR_FACT_PASSES: tuple[NamedPass, ...] = (("color", color_statement_facts),)
