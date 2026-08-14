"""Scalar SWAP facts over the compiler's complete inline template."""

from __future__ import annotations

import struct
from collections.abc import Iterable
from dataclasses import dataclass

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


SWAP_FACT_PASSES: tuple[NamedPass, ...] = (("scalar-swap", swap_statement_facts),)
