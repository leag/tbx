from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from tbd.compiler_ops import CompilerOp, translate_operations
from tbd.facts import Evidence, NamedPass, fact_key, reads
from tbd.ir import Fact, Operation
from tbd.operation_helpers import ax_reload_scratch as _ax_reload_scratch
from tbd.pool import static_array_at
from tbd.semantic import Resolved, combine_evidence, resolve_expression, unique_fact
from tbd.slots import VAR_BASE

_ARRAY_BLOCK = 0x36
_COMMON_BASE = 0x110
_BOUND_CELLS = ((0x08, 0x0A), (0x0E, 0x10), (0x14, 0x16))
_TYPES = {
    0x00: ("integer", "%", 2),
    0x02: ("long", "&", 4),
    0x04: ("float", "", 4),
    0x06: ("double", "#", 8),
    0x0A: ("string", "$", 4),
}


@dataclass(frozen=True)
class DimBracket:
    """One compiler bracket delimiting a runtime DIM operation."""

    start: int
    dispatch_start: int
    end: int
    block: int
    kind: str
    evidence: tuple[int, ...]


@dataclass(frozen=True)
class DynamicDim:
    """Recovered runtime DIM declaration and its bounds."""

    start: int
    end: int
    dispatch_end: int
    name: str
    bounds: tuple[object, ...]
    dynamic: bool
    option_base: int | None
    evidence: tuple[int, ...]


@reads(
    "layout.array",
    "layout.pool",
    "tb.fn_call",
    "tb.fn_return",
    "tb.fp",
    "tb.fp_far",
    "tb.fwait",
    "tb.runtime",
    "tb.statement",
    "x86.inc",
    "x86.j",
    "x86.jmp",
    "x86.mov_acc_mem",
    "x86.mov_imm",
)
def runtime_array_layout_facts(
    evidence: Evidence, facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Recover the runtime array descriptor layout."""

    layout = unique_fact(facts, "layout.pool", ("dgroup",))
    brackets = _dim_brackets(translate_operations(evidence.instructions))
    blocks = tuple(sorted({item.block for item in brackets}))
    static_count = len([fact for fact in facts if fact.kind == "layout.array"])
    pool_ds = layout.value[0] if layout is not None and layout.value else None
    ds = _runtime_ds(evidence.image, blocks, pool_ds)
    if ds is None:
        return
    if blocks[:1] == (_COMMON_BASE,):
        static_count = _common_static_count(evidence.image, ds, blocks)
    grid = _runtime_grid(blocks, static_count)
    if grid is None:
        return
    n_static, scalar_base, common = grid
    records = []
    for index, block in enumerate(blocks):
        record = _runtime_record(evidence.image, ds, block)
        if record is None:
            return
        kind, suffix, width, rank = record
        name = f"V{n_static + index}{suffix}"
        records.append((block, name, kind, rank, width))
    support = combine_evidence(*(item.evidence for item in brackets))
    yield Fact(
        "layout.runtime_grid",
        ("dgroup",),
        (blocks, n_static, scalar_base, common, ds),
        support,
        "anchored",
    )
    for index, (block, name, kind, rank, width) in enumerate(records):
        yield Fact(
            "layout.runtime_array",
            ("runtime", block),
            (n_static + index, name, kind, rank, width, common),
            support,
            "anchored",
        )


@reads(
    "constant",
    "expression.system",
    "layout.array",
    "layout.runtime_array",
    "machine.store",
    "slot",
    "tb.fn_call",
    "tb.fn_return",
    "tb.fp",
    "tb.fp_far",
    "tb.fwait",
    "tb.runtime",
    "tb.statement",
    "x86.inc",
    "x86.j",
    "x86.jmp",
    "x86.mov_acc_mem",
    "x86.mov_imm",
)
def dynamic_dim_facts(evidence: Evidence, facts: frozenset[Fact]) -> Iterable[Fact]:
    """Recover dynamic DIM statements from descriptor operations."""

    brackets = _dim_brackets(translate_operations(evidence.instructions))
    opens: dict[int, DimBracket] = {}
    dims = []
    instructions = {item.offset: item for item in evidence.instructions}
    by_end = {item.end: item for item in evidence.instructions}
    for bracket in brackets:
        if bracket.kind == "dim_begin":
            opens[bracket.block] = bracket
            continue
        opening = opens.pop(bracket.block, None)
        layout = unique_fact(facts, "layout.runtime_array", ("runtime", bracket.block))
        if opening is None or layout is None:
            continue
        dim = _dynamic_dim(opening, bracket, layout, facts, instructions, by_end)
        if dim is not None:
            dims.append(dim)
    yield from _fold_dim_chains(tuple(dims))


def _dim_brackets(operations: tuple[CompilerOp, ...]) -> tuple[DimBracket, ...]:
    found = []
    for index in range(len(operations) - 3):
        setup, segment, load, dispatch = operations[index : index + 4]
        if (
            (setup.kind, segment.kind, load.kind) != ("movsi", "movdx", "movesdx")
            or dispatch.kind not in {"dim_begin", "dim_end"}
            or not setup.args
            or not isinstance(setup.args[0], int)
            or setup.end != segment.offset
            or segment.end != load.offset
            or load.end != dispatch.offset
        ):
            continue
        found.append(
            DimBracket(
                setup.offset,
                dispatch.offset,
                dispatch.end,
                setup.args[0],
                dispatch.kind,
                (setup.offset, segment.offset, load.offset, dispatch.offset),
            )
        )
    return tuple(found)


def _runtime_grid(
    blocks: tuple[int, ...], static_count: int
) -> tuple[int, int, bool] | None:
    if not blocks or any(
        right - left != _ARRAY_BLOCK for left, right in zip(blocks, blocks[1:])
    ):
        return None
    first = blocks[0]
    if first == _COMMON_BASE:
        static_base = (blocks[-1] + _ARRAY_BLOCK + 15) & ~15
        static_base += 0x10
        scalar_base = static_base + _ARRAY_BLOCK * static_count
        return static_count, scalar_base, True
    if first < VAR_BASE:
        return None
    n_static, remainder = divmod(first - VAR_BASE, _ARRAY_BLOCK)
    if remainder:
        return static_count, blocks[-1] + _ARRAY_BLOCK, False
    return n_static, VAR_BASE + _ARRAY_BLOCK * (n_static + len(blocks)), False


def _runtime_record(
    image: bytes, ds: int, block: int
) -> tuple[str, str, int, int] | None:
    offset = ds + block
    if offset < 0 or offset + 4 > len(image):
        return None
    type_byte, rank = image[offset + 2], image[offset + 3]
    record = _TYPES.get(type_byte)
    if record is None or rank not in {1, 2, 3}:
        return None
    kind, suffix, width = record
    return kind, suffix, width, rank


def _common_static_count(image: bytes, ds: int, blocks: tuple[int, ...]) -> int:
    static_base = (blocks[-1] + _ARRAY_BLOCK + 15) & ~15
    static_base += 0x10
    count = 0
    while (
        static_array_at(
            image,
            ds + static_base + count * _ARRAY_BLOCK,
            static_base + count * _ARRAY_BLOCK,
        )
        is not None
    ):
        count += 1
    return count


def _runtime_ds(image: bytes, blocks: tuple[int, ...], pool_ds: object) -> int | None:

    if not blocks:
        return None
    candidates = []
    stop = len(image) - blocks[-1] - 3
    for ds in range(0, max(0, stop), 16):
        if all(_runtime_record(image, ds, block) is not None for block in blocks):
            candidates.append(ds)
    if not candidates:
        return None
    if len(candidates) == 1:
        return candidates[0]
    if not isinstance(pool_ds, int):
        return None
    distances = sorted((abs(ds - pool_ds), ds) for ds in candidates)
    if len(distances) > 1 and distances[0][0] == distances[1][0]:
        return None
    return distances[0][1]


def _dynamic_dim(
    opening: DimBracket,
    closing: DimBracket,
    layout: Fact,
    facts: frozenset[Fact],
    instructions: dict[int, Operation],
    by_end: dict[int, Operation],
) -> DynamicDim | None:
    _index, name, _kind, rank, _width, common = layout.value
    if not isinstance(name, str) or not isinstance(rank, int):
        return None
    cells = _bound_cell_facts(facts, opening.block, rank, opening.end, closing.start)
    if cells is None:
        return None
    resolved = {}
    support = [opening.evidence, closing.evidence]
    for displacement, effect in cells.items():
        value = _bound_value(effect, facts, instructions, by_end)
        if value is None:
            return None
        resolved[displacement] = value.value
        support.extend((effect.evidence, value.evidence))
    order = tuple(cells)
    bounds = []
    base_values = set()
    for low_cell, high_cell in _BOUND_CELLS[:rank]:
        low, high = resolved[low_cell], resolved[high_cell]
        explicit = order.index(low_cell) < order.index(high_cell)
        if not explicit and low not in {("const", 0), ("const", 1)}:
            return None
        if not explicit:
            if not isinstance(low, tuple) or len(low) < 2:
                return None
            base_values.add(low[1])
        bounds.append((low, high) if explicit else high)
    if len(base_values) > 1:
        return None
    dynamic = not common and all(_constant_high(bound) for bound in bounds)
    return DynamicDim(
        opening.start,
        closing.end,
        closing.end,
        name,
        tuple(bounds),
        dynamic,
        next(iter(base_values)) if base_values else None,
        combine_evidence(*support),
    )


def _bound_cell_facts(
    facts: frozenset[Fact], block: int, rank: int, start: int, end: int
) -> dict[int, Fact] | None:
    expected = {cell for pair in _BOUND_CELLS[:rank] for cell in pair}
    matches = []
    for fact in facts:
        if fact.kind != "machine.store" or not fact.subject or not fact.evidence:
            continue
        address, source = fact.subject[0], fact.evidence[0]
        if (
            isinstance(address, int)
            and address - block in expected
            and start <= source < end
        ):
            matches.append((source, address - block, fact))
    matches.sort(key=lambda item: item[0])
    if len(matches) != len(expected) or {item[1] for item in matches} != expected:
        return None
    return {displacement: fact for _source, displacement, fact in matches}


def _bound_value(
    effect: Fact,
    facts: frozenset[Fact],
    instructions: dict[int, Operation],
    by_end: dict[int, Operation],
) -> Resolved | None:
    value = effect.value[0] if effect.value else None
    resolved = resolve_expression(value, facts)
    if resolved is not None:
        return resolved
    store = instructions.get(effect.evidence[-1]) if effect.evidence else None
    reload = by_end.get(store.offset) if store is not None else None
    scratch = _ax_reload_scratch(reload)
    if reload is None or scratch is None:
        return None
    candidates = [
        fact
        for fact in facts
        if fact.kind == "machine.store"
        and fact.subject == (scratch,)
        and fact.evidence
        and fact.evidence[-1] < reload.offset
    ]
    if not candidates:
        return None
    scratch_effect = max(
        candidates, key=lambda fact: (fact.evidence[-1], fact_key(fact))
    )
    return resolve_expression(scratch_effect.value[0], facts)


def _constant_high(bound: object) -> bool:
    high = (
        bound[1]
        if isinstance(bound, tuple) and len(bound) == 2 and isinstance(bound[0], tuple)
        else bound
    )
    return (
        isinstance(high, tuple)
        and len(high) == 2
        and high[0] == "const"
        and isinstance(high[1], int)
    )


def _fold_dim_chains(dims: tuple[DynamicDim, ...]) -> Iterable[Fact]:
    ordered = sorted(dims, key=lambda item: item.start)
    index = 0
    while index < len(ordered):
        chain = [ordered[index]]
        index += 1
        while index < len(ordered) and chain[-1].dispatch_end == ordered[index].start:
            chain.append(ordered[index])
            index += 1
        first, last = chain[0], chain[-1]
        also = tuple((item.name, item.bounds) for item in chain[1:])
        for item in chain:
            if item.option_base is not None:
                yield Fact(
                    "option.base",
                    ("program",),
                    (item.option_base,),
                    item.evidence,
                    "anchored",
                )
        yield Fact(
            "semantic.dynamic_dim",
            (first.start, last.end),
            (first.name, first.bounds, also, first.dynamic),
            combine_evidence(*(item.evidence for item in chain)),
            "anchored",
        )


RUNTIME_ARRAY_LAYOUT_PASSES: tuple[NamedPass, ...] = (
    ("runtime-array-layout", runtime_array_layout_facts),
)

DYNAMIC_DIM_PASSES: tuple[NamedPass, ...] = (("dynamic-dim", dynamic_dim_facts),)
