"""Memory-access and constant-pool facts derived from immutable evidence."""

from __future__ import annotations

import struct
from collections.abc import Iterable

from tbd.facts import Evidence, NamedPass
from tbd.ir import Fact, Operation
from tbd.pool import decode_literal, infer_layout
from tbd.slots import VAR_BASE


def memory_access_facts(
    evidence: Evidence, _facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Describe supported direct memory reads and writes."""

    for instruction in evidence.instructions:
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
    """Recognize the address load consumed by the string-read runtime helper."""

    for left, right in zip(evidence.instructions, evidence.instructions[1:]):
        if not _is_string_reference(left, right):
            continue
        yield Fact(
            "memory.read",
            (left.operands[1],),
            ("string",),
            (left.offset, right.offset),
            "signature",
        )


def constant_pool_facts(
    evidence: Evidence, facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Infer one anchored pool layout and decode its referenced literals."""

    writes = _addresses(facts, "memory.write")
    references = _references(facts)
    if not writes and not references:
        return
    layout = infer_layout(evidence.image, writes, references)
    if layout is None:
        return
    support = _support(facts, {"memory.read", "memory.write"}) + (layout.marker,)
    yield Fact(
        "layout.pool",
        ("dgroup",),
        (layout.ds, layout.pool_base, layout.marker, layout.string_base),
        support,
        "anchored",
    )
    for address, kind in references:
        literal = decode_literal(evidence.image, layout, address, kind)
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
    if vector in (0x35, 0x3B) and reg in (0, 3):
        action = "read" if reg == 0 else "write"
        kind = "integer" if vector == 0x3B else "float"
        return ((action, address, kind),)
    if vector in (0x34, 0x36):
        return (("read", address, "float"),)
    return None


def _is_string_reference(left: Operation, right: Operation) -> bool:
    return (
        left.kind == "x86.mov_imm"
        and left.operands[0] == "si"
        and right.kind == "tb.runtime"
        and right.operands == (0x9C,)
        and left.end == right.offset
    )


def _addresses(facts: frozenset[Fact], kind: str) -> set[int]:
    return {
        fact.subject[0]
        for fact in facts
        if fact.kind == kind
        and fact.subject
        and isinstance(fact.subject[0], int)
        and fact.subject[0] >= VAR_BASE
    }


def _references(facts: frozenset[Fact]) -> tuple[tuple[int, str], ...]:
    return tuple(
        sorted(
            {
                (fact.subject[0], fact.value[0])
                for fact in facts
                if fact.kind == "memory.read"
                and fact.subject
                and fact.value
                and isinstance(fact.subject[0], int)
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
                if fact.kind == "memory.read"
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
