"""OPEN facts over the compiler's two complete source scaffolds."""

from __future__ import annotations

import struct
from collections.abc import Iterable
from dataclasses import dataclass

from tbd.facts import Evidence, NamedPass
from tbd.ir import Fact, Operation
from tbd.semantic import combine_evidence, resolve_expression

_OPEN_MODES = frozenset({"A", "B", "I", "O", "R"})


@dataclass(frozen=True)
class OpenMatch:
    """One complete comma-form or FOR-AS OPEN scaffold."""

    start: int
    end: int
    file_address: int
    mode_address: int | None
    mode: str | None
    number: int
    record_length: int
    for_as: bool
    evidence: tuple[int, ...]


def open_matches(instructions: tuple[Operation, ...]) -> tuple[OpenMatch, ...]:
    """Return every complete OPEN template without consulting semantic facts."""

    matches = []
    for index in range(len(instructions) - 6):
        window = instructions[index : index + 7]
        match = _comma_open(window) or _for_as_open(window)
        if match is not None:
            matches.append(match)
    return tuple(matches)


def open_statement_facts(
    evidence: Evidence, facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Resolve complete OPEN matches into exact source-shaped facts."""

    for match in open_matches(evidence.instructions):
        file_name = resolve_expression(
            ("memory", match.file_address, "string"), facts
        )
        if file_name is None or not _supported_file_name(
            file_name.value, match, facts
        ):
            continue
        if match.mode is None:
            resolved_mode = resolve_expression(
                ("memory", match.mode_address, "string"), facts
            )
            if (
                resolved_mode is None
                or not isinstance(resolved_mode.value, tuple)
                or resolved_mode.value[:1] != ("string",)
                or len(resolved_mode.value) != 2
                or resolved_mode.value[1] not in _OPEN_MODES
            ):
                continue
            mode = resolved_mode.value
            mode_evidence = resolved_mode.evidence
        else:
            mode = "string", match.mode
            mode_evidence = ()
        record_length = (
            None
            if match.record_length == 128
            else ("const", match.record_length)
        )
        yield Fact(
            "semantic.open",
            (match.start, match.end),
            (
                mode,
                match.number,
                file_name.value,
                record_length,
                match.for_as,
            ),
            combine_evidence(
                match.evidence,
                file_name.evidence,
                mode_evidence,
            ),
            "anchored",
        )


def _comma_open(window: tuple[Operation, ...]) -> OpenMatch | None:
    if len(window) != 7 or not _contiguous(window):
        return None
    number_store, file_setup, file_read, mode_setup, mode_read, length_load, open_ = (
        window
    )
    number = _word_store(number_store, 0x60)
    file_address = _string_read(file_setup, file_read)
    mode_address = _string_read(mode_setup, mode_read)
    record_length = _immediate_ax(length_load)
    if (
        number is None
        or file_address is None
        or mode_address is None
        or record_length is None
        or not _is_open(open_)
    ):
        return None
    return OpenMatch(
        window[0].offset,
        window[-1].end,
        file_address,
        mode_address,
        None,
        number,
        record_length,
        False,
        tuple(instruction.offset for instruction in window),
    )


def _supported_file_name(
    value: object, match: OpenMatch, facts: frozenset[Fact]
) -> bool:
    if not isinstance(value, tuple) or value[:1] != ("slot",):
        return True
    return any(
        fact.kind == "memory.write"
        and fact.subject == (match.file_address,)
        and fact.evidence
        and fact.evidence[-1] < match.start
        for fact in facts
    )


def _for_as_open(window: tuple[Operation, ...]) -> OpenMatch | None:
    if len(window) != 7 or not _contiguous(window):
        return None
    file_setup, file_read, mode_store, mode_push, number_store, length_load, open_ = (
        window
    )
    file_address = _string_read(file_setup, file_read)
    packed_mode = _word_store(mode_store, 0x2E)
    number = _word_store(number_store, 0x60)
    record_length = _immediate_ax(length_load)
    mode = None if packed_mode is None else chr(packed_mode >> 8)
    if (
        file_address is None
        or packed_mode is None
        or packed_mode & 0xFF != 1
        or mode not in _OPEN_MODES
        or mode_push.kind != "tb.runtime"
        or mode_push.operands != (0xCD,)
        or number is None
        or record_length is None
        or not _is_open(open_)
    ):
        return None
    return OpenMatch(
        window[0].offset,
        window[-1].end,
        file_address,
        None,
        mode,
        number,
        record_length,
        True,
        tuple(instruction.offset for instruction in window),
    )


def _word_store(instruction: Operation, address: int) -> int | None:
    raw = bytes.fromhex(instruction.raw)
    if len(raw) != 6 or raw[:2] != b"\xc7\x06":
        return None
    actual, value = struct.unpack_from("<HH", raw, 2)
    return value if actual == address else None


def _string_read(setup: Operation, runtime: Operation) -> int | None:
    if (
        setup.kind != "x86.mov_imm"
        or len(setup.operands) != 2
        or setup.operands[0] != "si"
        or not isinstance(setup.operands[1], int)
        or setup.end != runtime.offset
        or runtime.kind != "tb.runtime"
        or runtime.operands != (0x9C,)
    ):
        return None
    return setup.operands[1]


def _immediate_ax(instruction: Operation) -> int | None:
    if (
        instruction.kind != "x86.mov_imm"
        or instruction.operands[:1] != ("ax",)
        or len(instruction.operands) != 2
        or not isinstance(instruction.operands[1], int)
    ):
        return None
    return instruction.operands[1]


def _is_open(instruction: Operation) -> bool:
    return (
        instruction.kind == "tb.statement"
        and instruction.operands[:2] == ("OPEN", 0x82)
    )


def _contiguous(instructions: tuple[Operation, ...]) -> bool:
    return all(
        left.end == right.offset
        for left, right in zip(instructions, instructions[1:])
    )


OPEN_FACT_PASSES: tuple[NamedPass, ...] = (("open", open_statement_facts),)
