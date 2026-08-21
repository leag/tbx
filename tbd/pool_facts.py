"""Memory-access and constant-pool facts derived from immutable evidence."""

from __future__ import annotations

import struct
from collections.abc import Iterable

from tbd.facts import Evidence, NamedPass
from tbd.ir import Fact, Operation
from tbd.pool import array_at, decode_literal, infer_layout
from tbd.profile import FP_ARITHMETIC_TYPES, FP_TRANSFER_TYPES
from tbd.slots import VAR_BASE
from tbd.swap_facts import scalar_swap_matches


def memory_access_facts(
    evidence: Evidence, _facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Describe supported direct memory reads and writes."""

    claimed = {
        offset
        for match in scalar_swap_matches(evidence.instructions)
        for offset in match.evidence
    }
    for instruction in evidence.instructions:
        if instruction.offset in claimed:
            continue
        for action, address, kind in _memory_accesses(instruction):
            yield Fact(
                f"memory.{action}",
                (address,),
                (kind,),
                (instruction.offset,),
                "structural",
            )


def string_reference_facts(
    evidence: Evidence, _facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Recognize direct string reads and writes through the SI runtime ABI."""

    for left, right in zip(evidence.instructions, evidence.instructions[1:]):
        access = _string_access(left, right)
        if access is None:
            continue
        action, address = access
        yield Fact(
            f"memory.{action}",
            (address,),
            ("string",),
            (left.offset, right.offset),
            "signature",
        )


def constant_pool_facts(
    evidence: Evidence, facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Infer one anchored pool layout and decode its referenced literals."""

    writes = _addresses(facts, "memory.write")
    write_widths = _write_widths(facts)
    references = _references(facts)
    if not writes and not references:
        return
    array_slots, array_data, array_support = _array_witnesses(evidence.instructions)
    runtime_blocks = _runtime_dim_blocks(evidence.instructions)
    common_blocks = runtime_blocks if runtime_blocks[:1] == (0x110,) else ()
    static_base = (
        _align16(common_blocks[-1] + 0x36) + 0x10
        if common_blocks
        else VAR_BASE
    )
    if common_blocks:
        writes = {address for address in writes if address >= static_base}
        write_widths = tuple(
            item for item in write_widths if item[0] >= static_base
        )
        references = tuple(
            item for item in references if item[0] >= static_base
        )
    if runtime_blocks:
        writes = {
            address
            for address in writes
            if not _inside_runtime_block(address, runtime_blocks)
        }
        write_widths = tuple(
            item
            for item in write_widths
            if not _inside_runtime_block(item[0], runtime_blocks)
        )
        references = tuple(
            item
            for item in references
            if not _inside_runtime_block(item[0], runtime_blocks)
        )
    layout = infer_layout(
        evidence.image,
        writes,
        references,
        array_slots,
        array_data,
        static_base,
        common_blocks,
        write_widths,
    )
    if layout is None:
        return
    support = (
        _support(facts, {"memory.read", "memory.write"})
        + array_support
        + (layout.marker,)
    )
    yield Fact(
        "layout.pool",
        ("dgroup",),
        (layout.ds, layout.pool_base, layout.marker, layout.string_base),
        support,
        "anchored",
    )
    array_count = len(layout.arrays)
    for record_index, array in enumerate(layout.arrays):
        source_index = array_count - 1 - record_index
        suffix = {
            "integer": "%",
            "long": "&",
            "double": "#",
            "string": "$",
        }.get(array.kind, "")
        yield Fact(
            "layout.array",
            ("static", array.slot),
            (
                source_index,
                f"V{source_index}{suffix}",
                array.bounds,
                array.kind,
                array.base,
                array.element_size,
                array.count,
            ),
            (array.record, layout.marker),
            "anchored",
        )
    for address, kind in references:
        if array_at(layout, address) is not None:
            continue
        literal = (
            ("string", "")
            if kind == "string" and address == layout.pool_base - 4
            else decode_literal(evidence.image, layout, address, kind)
        )
        if literal is None:
            continue
        subject = ("string", address) if kind == "string" else ("memory", address)
        evidence_addresses = _reference_support(facts, address, kind) + (layout.marker,)
        yield Fact(
            "constant",
            subject,
            literal,
            tuple(sorted(set(evidence_addresses))),
            "anchored",
        )


def _memory_accesses(instruction: Operation) -> tuple[tuple[str, int, str], ...]:
    raw = bytes.fromhex(instruction.raw)
    if access := _native_fp_access(raw):
        return access
    if access := _fp_access(instruction, raw):
        return access
    if len(raw) >= 4 and raw[:2] in {b"\xc7\x06", b"\x89\x06"}:
        return (("write", struct.unpack_from("<H", raw, 2)[0], "integer"),)
    if len(raw) == 4 and raw[:2] in {b"\x01\x06", b"\x29\x06"}:
        address = struct.unpack_from("<H", raw, 2)[0]
        return ("read", address, "integer"), ("write", address, "integer")
    if len(raw) == 4 and raw[:2] == b"\x8b\x06":
        return (("read", struct.unpack_from("<H", raw, 2)[0], "integer"),)
    if instruction.kind == "x86.mov_acc_mem":
        action = "write" if instruction.operands[1] == "store" else "read"
        return ((action, instruction.operands[0], "integer"),)
    return ()


def instruction_memory_accesses(
    instruction: Operation,
) -> tuple[tuple[str, int, str], ...]:
    """Expose calibrated direct-memory roles to other independent fact passes."""

    return _memory_accesses(instruction)


def _native_fp_access(
    raw: bytes,
) -> tuple[tuple[str, int, str], ...] | None:
    if len(raw) != 4 or raw[0] not in range(0xD8, 0xE0):
        return None
    modrm = raw[1]
    if modrm >> 6 != 0 or modrm & 7 != 6:
        return None
    address = struct.unpack_from("<H", raw, 2)[0]
    register = (modrm >> 3) & 7
    transfer = {0xD9: "float", 0xDB: "long", 0xDD: "double", 0xDF: "integer"}
    arithmetic = {0xD8: "float", 0xDA: "long", 0xDC: "double", 0xDE: "integer"}
    if raw[0] in transfer and register in {0, 3}:
        action = "read" if register == 0 else "write"
        return ((action, address, transfer[raw[0]]),)
    if raw[0] in arithmetic:
        return (("read", address, arithmetic[raw[0]]),)
    return None


def _array_witnesses(
    instructions: tuple[Operation, ...],
) -> tuple[tuple[int, ...], tuple[int, ...], tuple[int, ...]]:
    slots = []
    data = []
    support = []
    for index, instruction in enumerate(instructions):
        slot_match = _array_slot_witness(instructions, index)
        if slot_match is not None:
            slot, sources = slot_match
            slots.append(slot)
            support.extend(sources)
        raw = bytes.fromhex(instruction.raw)
        if len(raw) == 4 and raw[:2] == b"\x81\xc6":
            address = struct.unpack_from("<H", raw, 2)[0]
            if address >= VAR_BASE:
                data.append(address)
                support.append(instruction.offset)
    return (
        tuple(sorted(set(slots))),
        tuple(sorted(set(data))),
        tuple(sorted(set(support))),
    )


def _array_slot_witness(
    instructions: tuple[Operation, ...], index: int
) -> tuple[int, tuple[int, ...]] | None:
    setup = instructions[index]
    if (
        setup.kind != "x86.mov_imm"
        or setup.operands[0] != "si"
        or not isinstance(setup.operands[1], int)
    ):
        return None
    direct = instructions[index + 1 : index + 2]
    if direct and _gfx_statement(direct[0]) and setup.end == direct[0].offset:
        return setup.operands[1], (setup.offset, direct[0].offset)
    far = instructions[index + 1 : index + 4]
    if (
        len(far) == 3
        and far[0].kind == "x86.mov_imm"
        and far[0].operands[0] == "dx"
        and bytes.fromhex(far[1].raw) == b"\x8e\xc2"
        and _gfx_statement(far[2])
        and setup.end == far[0].offset
        and far[0].end == far[1].offset
        and far[1].end == far[2].offset
    ):
        return setup.operands[1], (
            setup.offset,
            far[0].offset,
            far[1].offset,
            far[2].offset,
        )
    return None


def _gfx_statement(instruction: Operation) -> bool:
    return (
        instruction.kind == "tb.statement"
        and instruction.operands[:1] in {("GET_GFX",), ("PUT_GFX",)}
    )


def _pushes_far_si(instructions: tuple[Operation, ...], index: int) -> bool:
    tail = instructions[index : index + 5]
    for left, right in zip(tail, tail[1:]):
        if (
            bytes.fromhex(left.raw) == b"\x06"
            and bytes.fromhex(right.raw) == b"\x56"
            and left.end == right.offset
        ):
            return True
    return False


def _runtime_dim_blocks(instructions: tuple[Operation, ...]) -> tuple[int, ...]:
    blocks = set()
    for index, setup in enumerate(instructions[:-3]):
        segment, load, dispatch = instructions[index + 1 : index + 4]
        if (
            setup.kind == "x86.mov_imm"
            and setup.operands[0] == "si"
            and isinstance(setup.operands[1], int)
            and segment.kind == "x86.mov_imm"
            and segment.operands[0] == "dx"
            and bytes.fromhex(load.raw) == b"\x8e\xc2"
            and dispatch.kind == "tb.statement"
            and dispatch.operands[:1] in {("DIM_BEGIN",), ("DIM_END",)}
            and setup.end == segment.offset
            and segment.end == load.offset
            and load.end == dispatch.offset
        ):
            blocks.add(setup.operands[1])
    return tuple(sorted(blocks))


def _inside_runtime_block(address: int, blocks: tuple[int, ...]) -> bool:
    return any(block <= address < block + 0x36 for block in blocks)


def _align16(value: int) -> int:
    return (value + 15) & ~15


def _fp_access(
    instruction: Operation, raw: bytes
) -> tuple[tuple[str, int, str], ...] | None:
    if instruction.kind != "tb.fp" or len(raw) < 5:
        return None
    vector, modrm = raw[1], raw[2]
    if modrm >> 6 != 0 or modrm & 7 != 6:
        return None
    address = struct.unpack_from("<H", raw, 3)[0]
    reg = (modrm >> 3) & 7
    if vector in FP_TRANSFER_TYPES and reg in (0, 3):
        action = "read" if reg == 0 else "write"
        kind = FP_TRANSFER_TYPES[vector]
        return ((action, address, kind),)
    if vector in FP_ARITHMETIC_TYPES:
        return (("read", address, FP_ARITHMETIC_TYPES[vector]),)
    return None


def _string_access(
    left: Operation, right: Operation
) -> tuple[str, int] | None:
    if (
        left.kind != "x86.mov_imm"
        or left.operands[0] != "si"
        or not isinstance(left.operands[1], int)
        or right.kind != "tb.runtime"
        or left.end != right.offset
    ):
        return None
    action = {(0x9C,): "read", (0xA0,): "write"}.get(right.operands)
    return (action, left.operands[1]) if action is not None else None


def _addresses(facts: frozenset[Fact], kind: str) -> set[int]:
    return {
        fact.subject[0]
        for fact in facts
        if fact.kind == kind
        and fact.subject
        and isinstance(fact.subject[0], int)
        and fact.subject[0] >= VAR_BASE
    }


def _write_widths(facts: frozenset[Fact]) -> tuple[tuple[int, int], ...]:
    widths = {"integer": 2, "long": 4, "float": 4, "double": 8, "string": 4}
    grouped: dict[int, set[str]] = {}
    for fact in facts:
        if (
            fact.kind == "memory.write"
            and fact.subject
            and isinstance(fact.subject[0], int)
            and fact.value
            and fact.value[0] in widths
        ):
            grouped.setdefault(fact.subject[0], set()).add(fact.value[0])
    return tuple(
        (address, 4 if "string" in found else widths[next(iter(found))])
        for address, found in sorted(grouped.items())
        if "string" in found or len({widths[kind] for kind in found}) == 1
    )


def _references(facts: frozenset[Fact]) -> tuple[tuple[int, str], ...]:
    return tuple(
        sorted(
            {
                (fact.subject[0], fact.value[0])
                for fact in facts
                if fact.kind in {"memory.read", "reference.input_prompt"}
                and fact.subject
                and fact.value
                and isinstance(fact.subject[0], int)
                and fact.subject[0] >= VAR_BASE
                and isinstance(fact.value[0], str)
            }
        )
    )


def _support(facts: frozenset[Fact], kinds: set[str]) -> tuple[int, ...]:
    return tuple(
        sorted(
            {
                address
                for fact in facts
                if fact.kind in kinds
                for address in fact.evidence
            }
        )
    )


def _reference_support(
    facts: frozenset[Fact], address: int, kind: str
) -> tuple[int, ...]:
    return tuple(
        sorted(
            {
                source
                for fact in facts
                if fact.kind in {"memory.read", "reference.input_prompt"}
                and fact.subject == (address,)
                and fact.value == (kind,)
                for source in fact.evidence
            }
        )
    )


POOL_FACT_PASSES: tuple[NamedPass, ...] = (
    ("memory-accesses", memory_access_facts),
    ("string-references", string_reference_facts),
    ("constant-pool", constant_pool_facts),
)
