from __future__ import annotations

from collections.abc import Iterable

from tbd.facts import Evidence, NamedPass, reads
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


@reads(
    "constant",
    "layout.array",
    "layout.common_slot",
    "layout.pool",
    "layout.runtime_grid",
    "memory.read",
    "memory.write",
    "tb.statement",
)
def slot_facts(evidence: Evidence, facts: frozenset[Fact]) -> Iterable[Fact]:
    """Recover typed scalar slots from pool accesses."""
    """Infer typed scalar slots from layout and memory-access facts."""

    layouts = [fact for fact in facts if fact.kind == "layout.pool"]
    runtime_grids = [fact for fact in facts if fact.kind == "layout.runtime_grid"]
    # The same layout can be recorded twice with different support.
    if len({fact.value for fact in layouts}) == 1:
        layouts = [min(layouts, key=lambda fact: fact.evidence)]
    if len(layouts) != 1:
        if len(runtime_grids) == 1 and isinstance(runtime_grids[0].value[2], int):
            scalar_base = runtime_grids[0].value[2]
            for address, related in sorted(
                _runtime_grid_writes(facts, scalar_base).items()
            ):
                if resolve_array_element(address, facts) is not None:
                    continue
                types = tuple(sorted({fact.value[0] for fact in related}))
                support = tuple(
                    sorted(
                        {
                            *runtime_grids[0].evidence,
                            *(source for fact in related for source in fact.evidence),
                        }
                    )
                )
                yield Fact(
                    "slot",
                    (address,),
                    (_scalar_name(address, scalar_base), types),
                    support,
                    "anchored",
                )
        return
    layout = layouts[0]
    has_runtime_dim = any(
        instruction.kind == "tb.statement"
        and instruction.operands[:1] == ("DIM_BEGIN",)
        for instruction in evidence.instructions
    )
    if has_runtime_dim and not any(
        fact.kind == "layout.runtime_grid" for fact in facts
    ):
        return
    pool_base, marker = layout.value[1], layout.value[2]
    array_count = len([fact for fact in facts if fact.kind == "layout.array"])
    scalar_base = VAR_BASE + 0x36 * array_count
    if len(runtime_grids) == 1 and isinstance(runtime_grids[0].value[2], int):
        scalar_base = runtime_grids[0].value[2]
    accesses = _slot_accesses(facts, pool_base, scalar_base)
    for common in facts:
        if common.kind != "layout.common_slot":
            continue
        address = common.subject[0]
        order, kind, _width = common.value
        yield Fact(
            "slot",
            (address,),
            (f"COMMON{order:04d}", (kind,)),
            common.evidence,
            "anchored",
        )
    common_addresses = {
        fact.subject[0]
        for fact in facts
        if fact.kind == "layout.common_slot" and fact.subject
    }
    for address, related in sorted(accesses.items()):
        if address in common_addresses:
            continue
        types = tuple(sorted({fact.value[0] for fact in related}))
        support = tuple(
            sorted({marker, *(source for fact in related for source in fact.evidence)})
        )
        yield Fact(
            "slot",
            (address,),
            (_scalar_name(address, scalar_base), types),
            support,
            "anchored",
        )


def _runtime_grid_writes(
    facts: frozenset[Fact], scalar_base: int
) -> dict[int, list[Fact]]:
    found: dict[int, list[Fact]] = {}
    for fact in facts:
        if fact.kind != "memory.write" or not fact.subject or not fact.value:
            continue
        address = fact.subject[0]
        kind = fact.value[0]
        width = _TYPE_WIDTHS.get(kind) if isinstance(kind, str) else None
        if (
            isinstance(address, int)
            and isinstance(width, int)
            and address >= scalar_base
            and (address - scalar_base) % 2 == 0
        ):
            found.setdefault(address, []).append(fact)
    return found


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
    """Return whether a typed memory access identifies a scalar slot."""
    if fact.kind not in {"memory.read", "memory.write"} or not fact.subject:
        return False
    address = fact.subject[0]
    kind = fact.value[0] if fact.value else None
    width = _TYPE_WIDTHS.get(kind) if isinstance(kind, str) else None
    return (
        isinstance(address, int)
        and isinstance(width, int)
        and scalar_base <= address
        and (address + width <= pool_base or address == pool_base)
        and (address - scalar_base) % 2 == 0
    )


def _scalar_name(address: int, scalar_base: int) -> str:
    index = (address - scalar_base) // 4 + 1
    half = "H" if (address - scalar_base) % 4 else ""
    return f"V{index:04d}{half}"


def materialize_slots(facts: tuple[Fact, ...]) -> tuple[Slot, ...]:
    """Build stable source names for recovered scalar slots."""

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


_SCRATCH_END = 0x100
"""Cells below this address are the compiler's scratch, not variables."""


@reads("layout.pool")
def select_temp_slot_facts(
    evidence: Evidence, _facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Name the scratch cell a string SELECT CASE keeps its selector in.

    ``SELECT CASE s$`` stores the selector in a scratch string cell once and
    each ``CASE`` pushes that cell next to its guard for a string compare.
    Read as a variable, the arms become ``IF cell$ = guard`` against a value
    computed once, which is what the program does; left unnamed, the compare
    has no operand.  A cell is named only when it is both stored and compared.
    """
    instructions = evidence.instructions
    stored: dict[int, list[int]] = {}
    compared: dict[int, list[int]] = {}
    for index, (setup, runtime) in enumerate(zip(instructions, instructions[1:])):
        if (
            setup.kind != "x86.mov_imm"
            or setup.operands[:1] != ("si",)
            or len(setup.operands) != 2
            or not isinstance(setup.operands[1], int)
            or not 0 < setup.operands[1] < _SCRATCH_END
            or setup.end != runtime.offset
            or runtime.kind != "tb.runtime"
        ):
            continue
        cell = setup.operands[1]
        if runtime.operands == (0xA0,):
            stored.setdefault(cell, []).append(setup.offset)
        elif runtime.operands in {(0x9C,), (0x9E,)}:
            following = instructions[index + 2 : index + 7]
            if any(
                item.kind == "tb.runtime" and item.operands == (0x9A,)
                for item in following
            ):
                compared.setdefault(cell, []).append(setup.offset)
    # A real selector is kept as a double: ``fstp qword [cell]`` once, and
    # ``fcomp qword [cell]`` against each guard.
    doubles: dict[int, tuple[list[int], list[int]]] = {}
    for item in instructions:
        raw = bytes.fromhex(item.raw)
        if item.kind != "tb.fp" or len(raw) != 5:
            continue
        cell = int.from_bytes(raw[3:5], "little")
        if raw[:3] in {b"\xcd\x39\x1e", b"\xcd\x38\x1e"} and 0 < cell < _SCRATCH_END:
            uses = doubles.setdefault(cell, ([], []))
            uses[0 if raw[1] == 0x39 else 1].append(item.offset)
    # The compiler reuses a scratch cell for numeric SELECTs too; a cell also
    # read or written as a word is not a string variable.
    numeric = {
        int.from_bytes(raw[2:4], "little")
        for raw in (bytes.fromhex(item.raw) for item in instructions)
        if len(raw) >= 4 and raw[0] in (0x89, 0x8B, 0x3B, 0x39, 0xC7) and raw[1] == 0x06
    } | {
        int.from_bytes(raw[1:3], "little")
        for raw in (bytes.fromhex(item.raw) for item in instructions)
        if len(raw) == 3 and raw[0] in (0xA1, 0xA3)
    }
    for cell in sorted((stored.keys() & compared.keys()) - numeric):
        yield Fact(
            "slot",
            (cell,),
            (f"SEL{cell:03X}", ("string",)),
            tuple(sorted({*stored[cell], *compared[cell]})),
            "anchored",
        )
    for cell, (stores, compares) in sorted(doubles.items()):
        if stores and compares and cell not in numeric and cell not in stored:
            yield Fact(
                "slot",
                (cell,),
                (f"SEL{cell:03X}", ("double",)),
                tuple(sorted({*stores, *compares})),
                "anchored",
            )


SLOT_FACT_PASSES: tuple[NamedPass, ...] = (
    ("dgroup-slots", slot_facts),
    ("select-temp-slots", select_temp_slot_facts),
)
