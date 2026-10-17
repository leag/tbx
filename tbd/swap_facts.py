from __future__ import annotations

import struct
from collections.abc import Iterable
from dataclasses import dataclass

from tbd.compiler_ops import CompilerOp, operation_indexes, translate_operations
from tbd.facts import Evidence, NamedPass, indexed_facts, reads
from tbd.ir import Fact, Operation
from tbd.operation_helpers import contiguous as _contiguous
from tbd.operation_helpers import raw_bytes as _raw_bytes
from tbd.semantic import combine_evidence, resolve_expression, resolve_slot


@dataclass(frozen=True)
class ScalarSwapMatch:
    """Decoded scalar SWAP operation and its evidence span."""

    start: int
    end: int
    left: int
    right: int
    evidence: tuple[int, ...]


@dataclass(frozen=True)
class MixedStringArraySwapMatch:
    """Decoded mixed scalar/string-array SWAP operation."""

    start: int
    end: int
    array_end: int
    scalar: int
    evidence: tuple[int, ...]
    components: tuple[int, ...]


def scalar_swap_matches(
    instructions: tuple[Operation, ...],
) -> tuple[ScalarSwapMatch, ...]:
    """Find scalar SWAP instruction windows."""
    matches = []
    for index in range(len(instructions) - 5):
        window = instructions[index : index + 6]
        match = _scalar_swap(window)
        if match is not None:
            matches.append(match)
    return tuple(matches)


def mixed_string_array_swap_matches(
    instructions: tuple[Operation, ...],
) -> tuple[MixedStringArraySwapMatch, ...]:
    """Find mixed string-array SWAP instruction windows."""
    matches = []
    for index in range(len(instructions) - 9):
        window = instructions[index : index + 10]
        raw = tuple(_raw_bytes(instruction.raw) for instruction in window)
        if (
            len(raw[0]) != 4
            or raw[0][:2] != b"\x8b\x36"
            or raw[1:3] != (b"\xd1\xe6", b"\xd1\xe6")
            or len(raw[3]) != 4
            or raw[3][:2] != b"\x81\xc6"
            or len(raw[4]) != 4
            or raw[4][:2] != b"\x8b\x06"
            or raw[5] != b"\x87\x04"
            or len(raw[6]) != 4
            or raw[6][:2] != b"\x89\x06"
            or len(raw[7]) != 4
            or raw[7][:2] != b"\x8b\x06"
            or raw[8] != b"\x87\x44\x02"
            or len(raw[9]) != 4
            or raw[9][:2] != b"\x89\x06"
            or not _contiguous(window)
        ):
            continue
        low = struct.unpack_from("<H", raw[4], 2)[0]
        if (
            struct.unpack_from("<H", raw[6], 2)[0] != low
            or struct.unpack_from("<H", raw[7], 2)[0] != low + 2
            or struct.unpack_from("<H", raw[9], 2)[0] != low + 2
        ):
            continue
        matches.append(
            MixedStringArraySwapMatch(
                window[0].offset,
                window[-1].end,
                window[3].end,
                low,
                tuple(item.offset for item in window),
                tuple(item.offset for item in window[4:]),
            )
        )
    return tuple(matches)


@reads(
    "constant",
    "expression.system",
    "layout.array",
    "reference.array_address",
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
def swap_statement_facts(evidence: Evidence, facts: frozenset[Fact]) -> Iterable[Fact]:
    """Recover scalar and array SWAP statements."""
    for match in scalar_swap_matches(evidence.instructions):
        left = resolve_slot(match.left, facts)
        right = resolve_slot(match.right, facts)
        if left is None or right is None:
            continue
        yield Fact(
            "semantic.swap",
            (match.start, match.end),
            (left.value, right.value),
            combine_evidence(match.evidence, left.evidence, right.evidence),
            "anchored",
        )
    yield from _array_swap_facts(evidence, facts)


def _array_swap_facts(evidence: Evidence, facts: frozenset[Fact]) -> Iterable[Fact]:
    operations = translate_operations(evidence.instructions)
    indexes, by_offset = operation_indexes(operations)
    addresses = indexed_facts(
        (
            fact
            for fact in facts
            if fact.kind == "reference.array_address"
            and len(fact.subject) == 2
            and len(fact.value) == 4
        ),
        lambda fact: fact.subject[0],
    )
    for left in addresses.values():
        if left.value[3] is not False:
            continue
        save = by_offset.get(left.subject[1])
        if save is None or save.kind != "movm_ds" or len(save.args) != 1:
            continue
        right = addresses.get(save.end)
        if (
            right is None
            or right.value[3] is not True
            or left.value[1:3] != right.value[1:3]
        ):
            continue
        restore = by_offset.get(right.subject[1])
        if restore is None or restore.kind != "moves_m" or restore.args != save.args:
            continue
        width = left.value[2]
        tail_kinds = _array_swap_tail(width)
        if not tail_kinds:
            continue
        restore_index = indexes[restore.offset]
        tail = operations[restore_index + 1 : restore_index + 1 + len(tail_kinds)]
        if tuple(item.kind for item in tail) != tail_kinds or not _compiler_contiguous(
            (
                save,
                *operations[indexes[save.offset] + 1 : restore_index + 1],
                *tail,
            )
        ):
            continue
        support = combine_evidence(
            left.evidence,
            right.evidence,
            (save.offset, restore.offset, *(item.offset for item in tail)),
        )
        yield Fact(
            "semantic.swap",
            (left.subject[0], tail[-1].end),
            (left.value[0], right.value[0]),
            support,
            "anchored",
        )
    yield from _dynamic_array_swap_facts(operations, indexes, by_offset, addresses)
    yield from _mixed_string_array_swap_facts(evidence.instructions, facts)


def _dynamic_array_swap_facts(
    operations: tuple[CompilerOp, ...],
    indexes: dict[int, int],
    by_offset: dict[int, CompilerOp],
    addresses: dict[object, Fact],
) -> Iterable[Fact]:
    for left in addresses.values():
        if left.value[3] is not False:
            continue
        save = by_offset.get(left.subject[1])
        if save is None or save.kind != "movm_es" or len(save.args) != 1:
            continue
        right = addresses.get(save.end)
        if (
            right is None
            or right.value[3] is not True
            or left.value[1:3] != right.value[1:3]
        ):
            continue
        alias = by_offset.get(right.subject[1])
        if alias is None or alias.kind != "movds_m" or alias.args != save.args:
            continue
        tail_kinds = _dynamic_array_swap_tail(left.value[1], left.value[2])
        if not tail_kinds:
            continue
        alias_index = indexes[alias.offset]
        tail = operations[alias_index + 1 : alias_index + 1 + len(tail_kinds)]
        if (
            tuple(item.kind for item in tail) != tail_kinds
            or len(tail[-2].args) != 1
            or not _compiler_contiguous(
                (
                    save,
                    *operations[indexes[save.offset] + 1 : alias_index + 1],
                    *tail,
                )
            )
        ):
            continue
        yield Fact(
            "semantic.swap",
            (left.subject[0], tail[-1].end),
            (left.value[0], right.value[0]),
            combine_evidence(
                left.evidence,
                right.evidence,
                (save.offset, alias.offset, *(item.offset for item in tail)),
            ),
            "anchored",
        )


def _dynamic_array_swap_tail(kind: object, width: object) -> tuple[str, ...]:
    low = ("movbxax", "movax_bx", "far_xchgsi", "movm_ax_bx")
    high = ("movax_bx2", "far_xchgsi2", "movm_ax_bx2")
    restore = ("movdx", "movdsdx")
    if kind == "string" and width == 4:
        return low + high + restore
    if kind == "double" and width == 8:
        return (
            low
            + high
            + (
                "movax_bx4",
                "far_xchgsi4",
                "movm_ax_bx4",
                "movax_bx6",
                "far_xchgsi6",
                "movm_ax_bx6",
            )
            + restore
        )
    return ()


def _mixed_string_array_swap_facts(
    instructions: tuple[Operation, ...],
    facts: frozenset[Fact],
) -> Iterable[Fact]:
    addresses = {
        (fact.subject[0], fact.subject[1]): fact
        for fact in facts
        if fact.kind == "reference.array_address"
        and len(fact.subject) == 2
        and fact.value[1:] == ("string", 4, False)
    }
    for match in mixed_string_array_swap_matches(instructions):
        address = addresses.get((match.start, match.array_end))
        if address is None:
            continue
        scalar = resolve_expression(("memory", match.scalar, "string"), facts)
        if scalar is None:
            continue
        yield Fact(
            "semantic.swap",
            (match.start, match.end),
            (scalar.value, address.value[0]),
            combine_evidence(
                address.evidence,
                scalar.evidence,
                match.evidence,
            ),
            "anchored",
        )


def _array_swap_tail(width: object) -> tuple[str, ...]:
    low = ("movbxax", "far_movax_bx", "xchgsi", "far_movm_ax_bx")
    if width == 2:
        return low
    if width == 4:
        return low + ("far_movax_bx2", "xchgsi2", "far_movm_ax_bx2")
    return ()


def _scalar_swap(window: tuple[Operation, ...]) -> ScalarSwapMatch | None:
    raw = tuple(_raw_bytes(instruction.raw) for instruction in window)
    prefixes = (b"\x8b\x06", b"\x87\x06", b"\x89\x06") * 2
    if any(len(item) != 4 or item[:2] != prefix for item, prefix in zip(raw, prefixes)):
        return None
    if not _contiguous(window):
        return None
    addresses = tuple(struct.unpack_from("<H", item, 2)[0] for item in raw)
    left, right, left_store, left_high, right_high, high_store = addresses
    if (
        left_store != left
        or high_store != left_high
        or left_high != (left + 2) & 0xFFFF
        or right_high != (right + 2) & 0xFFFF
    ):
        return None
    return ScalarSwapMatch(
        window[0].offset,
        window[-1].end,
        left,
        right,
        tuple(instruction.offset for instruction in window),
    )


def _compiler_contiguous(instructions: tuple[CompilerOp, ...]) -> bool:
    return all(
        left.end == right.offset for left, right in zip(instructions, instructions[1:])
    )


SWAP_FACT_PASSES: tuple[NamedPass, ...] = (("scalar-swap", swap_statement_facts),)
