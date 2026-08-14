"""Framed Turbo Basic procedure facts over immutable control-flow evidence."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from tbd.facts import Evidence, NamedPass
from tbd.ir import Fact, Operation
from tbd.semantic import combine_evidence

_CALLS = {"x86.call", "x86.call_far"}
_JUMPS = {"x86.jmp", "x86.jmp_far"}


@dataclass(frozen=True)
class _Procedure:
    declaration: int
    entry: int
    end: int
    frame_pop: int
    evidence: tuple[int, ...]
    inline_body: tuple[int, int] | None = None


@dataclass(frozen=True)
class InlineProcedure:
    """A compiler-bracketed unframed SUB whose body is opaque inline bytes."""

    declaration: int
    entry: int
    body_end: int
    end: int
    evidence: tuple[int, ...]


def procedure_facts(
    evidence: Evidence, facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Recover complete framed or inline SUBs and calls to their entries."""

    procedures = _procedures(evidence)
    instructions = {
        instruction.offset: instruction for instruction in evidence.instructions
    }
    for procedure in procedures.values():
        if procedure.inline_body is not None:
            body_start, body_end = procedure.inline_body
            yield Fact(
                "semantic.inline",
                (body_start, body_end),
                (evidence.image[body_start:body_end].hex(),),
                procedure.evidence,
                "signature",
            )
        yield Fact(
            "semantic.sub_def",
            (procedure.declaration, procedure.end),
            (procedure.entry, _parameters(procedure.frame_pop)),
            procedure.evidence,
            "signature",
        )
    for flow in facts:
        if flow.kind != "flow.call" or len(flow.subject) != 2 or not flow.value:
            continue
        procedure = procedures.get(flow.value[0])
        instruction = instructions.get(flow.subject[0])
        if procedure is None or instruction is None or instruction.kind not in _CALLS:
            continue
        yield Fact(
            "semantic.call",
            flow.subject,
            (procedure.entry, _arguments(procedure.frame_pop)),
            combine_evidence(flow.evidence, procedure.evidence),
            "signature",
        )


def _procedures(evidence: Evidence) -> dict[int, _Procedure]:
    instructions = evidence.instructions
    entries = [
        index
        for index, instruction in enumerate(instructions)
        if instruction.kind == "tb.proc_enter"
    ]
    result = {}
    for position, index in enumerate(entries):
        limit = entries[position + 1] if position + 1 < len(entries) else len(instructions)
        returns = [
            instruction
            for instruction in instructions[index + 1 : limit]
            if instruction.kind == "tb.proc_return"
        ]
        if len(returns) != 1:
            continue
        entry = instructions[index]
        returned = returns[0]
        frame_pop = returned.operands[0] if returned.operands else None
        if not isinstance(frame_pop, int):
            continue
        bracket = _declaration_bracket(instructions, index, returned.end)
        declaration = bracket.offset if bracket is not None else entry.offset
        support = combine_evidence(
            (entry.offset, returned.offset),
            () if bracket is None else (bracket.offset,),
        )
        result[entry.offset] = _Procedure(
            declaration, entry.offset, returned.end, frame_pop, support
        )
    for inline in inline_procedure_regions(evidence):
        result[inline.entry] = _Procedure(
            inline.declaration,
            inline.entry,
            inline.end,
            0,
            inline.evidence,
            (inline.entry, inline.body_end),
        )
    return result


def inline_procedure_regions(evidence: Evidence) -> tuple[InlineProcedure, ...]:
    """Return uniquely bracketed far-call targets with an appended bare RETF."""

    instructions = evidence.instructions
    brackets = {
        instruction.end: instruction
        for instruction in instructions
        if instruction.kind in _JUMPS and instruction.operands
    }
    calls: dict[int, list[Operation]] = {}
    for instruction in instructions:
        if (
            instruction.kind == "x86.call_far"
            and instruction.operands
            and isinstance(instruction.operands[0], int)
        ):
            calls.setdefault(instruction.operands[0], []).append(instruction)
    result = []
    for entry, entry_calls in calls.items():
        bracket = brackets.get(entry)
        main = bracket.operands[0] if bracket and bracket.operands else None
        if not (
            bracket is not None
            and isinstance(main, int)
            and entry <= main - 1 < len(evidence.image)
            and evidence.image[main - 1] == 0xCB
        ):
            continue
        framed_entry = any(
            instruction.offset == entry and instruction.kind == "tb.proc_enter"
            for instruction in instructions
        )
        framed_return = any(
            instruction.kind == "tb.proc_return"
            and entry < instruction.offset
            and instruction.end == main
            for instruction in instructions
        )
        if framed_entry and framed_return and not _has_inline_port_io(
            evidence.image, entry, main - 1
        ):
            continue
        support = combine_evidence(
            (bracket.offset, main - 1),
            tuple(call.offset for call in entry_calls),
        )
        result.append(
            InlineProcedure(bracket.offset, entry, main - 1, main, support)
        )
    return tuple(sorted(result, key=lambda item: item.entry))


def _has_inline_port_io(image: bytes, start: int, end: int) -> bool:
    """Recognize a whole immediate-port sequence source cannot compile."""

    return any(
        image[offset] == 0xB0 and image[offset + 2] == 0xE6
        for offset in range(start, max(start, end - 3))
    )


def _declaration_bracket(
    instructions: tuple[Operation, ...], entry_index: int, body_end: int
) -> Operation | None:
    if entry_index == 0:
        return None
    candidate = instructions[entry_index - 1]
    target = candidate.operands[0] if candidate.operands else None
    if (
        candidate.kind in _JUMPS
        and candidate.end == instructions[entry_index].offset
        and isinstance(target, int)
        and target >= body_end
    ):
        return candidate
    return None


def _parameters(frame_pop: int) -> tuple[object, ...]:
    if frame_pop == 0:
        return ()
    return ("unresolved-frame", frame_pop)


def _arguments(frame_pop: int) -> tuple[object, ...]:
    if frame_pop == 0:
        return ()
    return ("unresolved-call-arguments", frame_pop)


PROCEDURE_FACT_PASSES: tuple[NamedPass, ...] = (
    ("procedures", procedure_facts),
)
