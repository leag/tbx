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


def procedure_facts(
    evidence: Evidence, facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Recover complete framed SUB regions and calls to their entry addresses."""

    procedures = _procedures(evidence.instructions)
    instructions = {
        instruction.offset: instruction for instruction in evidence.instructions
    }
    for procedure in procedures.values():
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


def _procedures(instructions: tuple[Operation, ...]) -> dict[int, _Procedure]:
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
    return result


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
