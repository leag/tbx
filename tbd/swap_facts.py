"""Scalar SWAP facts over the compiler's complete inline template."""

from __future__ import annotations

import struct
from collections.abc import Iterable
from dataclasses import dataclass

from tbd.compiler_ops import CompilerOp, operation_indexes, translate_operations
from tbd.facts import Evidence, NamedPass
from tbd.ir import Fact, Operation
from tbd.semantic import combine_evidence, resolve_slot


@dataclass(frozen=True)
class ScalarSwapMatch:
    """One exact six-word-operation scalar SWAP signature."""

    start: int
    end: int
    left: int
    right: int
    evidence: tuple[int, ...]


def scalar_swap_matches(
    instructions: tuple[Operation, ...],
) -> tuple[ScalarSwapMatch, ...]:
    """Return every complete scalar SWAP template in immutable evidence."""

    matches = []
    for index in range(len(instructions) - 5):
        window = instructions[index : index + 6]
        match = _scalar_swap(window)
        if match is not None:
            matches.append(match)
    return tuple(matches)


def swap_statement_facts(
    evidence: Evidence, facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Resolve a matched scalar SWAP only when both slots are anchored."""

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


def _array_swap_facts(
    evidence: Evidence, facts: frozenset[Fact]
) -> Iterable[Fact]:
    operations = translate_operations(evidence.instructions)
    indexes, by_offset = operation_indexes(operations)
    addresses = {
        fact.subject[0]: fact
        for fact in facts
        if fact.kind == "reference.array_address"
        and len(fact.subject) == 2
        and len(fact.value) == 4
    }
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
        if (
            restore is None
            or restore.kind != "moves_m"
            or restore.args != save.args
        ):
            continue
        width = left.value[2]
        tail_kinds = _array_swap_tail(width)
        if not tail_kinds:
            continue
        restore_index = indexes[restore.offset]
        tail = operations[restore_index + 1 : restore_index + 1 + len(tail_kinds)]
        if (
            tuple(item.kind for item in tail) != tail_kinds
            or not _compiler_contiguous(
                (
                    save,
                    *operations[indexes[save.offset] + 1 : restore_index + 1],
                    *tail,
                )
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


def _array_swap_tail(width: object) -> tuple[str, ...]:
    low = ("movbxax", "far_movax_bx", "xchgsi", "far_movm_ax_bx")
    if width == 2:
        return low
    if width == 4:
        return low + ("far_movax_bx2", "xchgsi2", "far_movm_ax_bx2")
    return ()


def _scalar_swap(window: tuple[Operation, ...]) -> ScalarSwapMatch | None:
    if not _contiguous(window):
        return None
    raw = tuple(bytes.fromhex(instruction.raw) for instruction in window)
    prefixes = (b"\x8b\x06", b"\x87\x06", b"\x89\x06") * 2
    if any(
        len(item) != 4 or item[:2] != prefix
        for item, prefix in zip(raw, prefixes)
    ):
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


def _contiguous(instructions: tuple[Operation, ...]) -> bool:
    return all(
        left.end == right.offset
        for left, right in zip(instructions, instructions[1:])
    )


def _compiler_contiguous(instructions: tuple[CompilerOp, ...]) -> bool:
    return all(
        left.end == right.offset
        for left, right in zip(instructions, instructions[1:])
    )


SWAP_FACT_PASSES: tuple[NamedPass, ...] = (("scalar-swap", swap_statement_facts),)
