"""FP FOR/NEXT facts translated from calibrated compiler templates."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from tbd.compiler_ops import CompilerOp, operation_indexes, translate_operations
from tbd.facts import Evidence, NamedPass
from tbd.for_facts import (
    ForEvidence,
    _assignment_ending,
    _for_evidence,
    _goto_instruction,
)
from tbd.for_templates import FpForTemplate, match_fp_for_test
from tbd.ir import Fact, Operation
from tbd.semantic import combine_evidence


@dataclass(frozen=True)
class FpHeader:
    """Three staged assignments and their initial jump to NEXT."""

    jump: Operation
    limit: Fact
    step: Fact
    variable: Fact


@dataclass(frozen=True)
class FpTail:
    """The translated FP STEP update immediately before the sign test."""

    start: int
    evidence: tuple[int, ...]


def fp_for_facts(evidence: Evidence, facts: frozenset[Fact]) -> Iterable[Fact]:
    """Translate the reference decoder's x87 FOR decisions into facts."""

    context = _for_evidence(evidence.instructions, facts)
    operations = translate_operations(evidence.instructions)
    indexes, _by_address = operation_indexes(operations)
    for goto in (fact for fact in facts if fact.kind == "flow.goto"):
        match = _fp_for_match(goto, context, operations, indexes)
        if match is None:
            continue
        header, template, tail = match
        support = combine_evidence(
            header.limit.evidence,
            header.step.evidence,
            header.variable.evidence,
            goto.evidence,
            tail.evidence,
            template.evidence,
        )
        yield Fact(
            "semantic.for",
            (header.limit.subject[0], header.jump.end),
            (
                header.variable.value[0],
                header.variable.value[1],
                header.limit.value[1],
                header.step.value[1],
            ),
            support,
            "anchored",
        )
        yield Fact(
            "semantic.next",
            (tail.start, template.end),
            (header.variable.value[0],),
            support,
            "anchored",
        )


def _fp_for_match(
    goto: Fact,
    context: ForEvidence,
    operations: tuple[CompilerOp, ...],
    indexes: dict[int, int],
) -> tuple[FpHeader, FpForTemplate, FpTail] | None:
    header = _fp_header(goto, context)
    if header is None:
        return None
    slots = tuple(
        _slot_address(assignment.value[0])
        for assignment in (header.limit, header.step, header.variable)
    )
    target = goto.value[0]
    index = indexes.get(target)
    if index is None or any(address is None for address in slots):
        return None
    template = match_fp_for_test(operations, index, slots)
    if template is None:
        return None
    tail = _fp_tail(
        target,
        template,
        context,
        operations,
        indexes,
    )
    if tail is None:
        return None
    if (template.body - header.jump.end) % 0x10000:
        return None
    return header, template, tail


def _fp_tail(
    end: int,
    template: FpForTemplate,
    context: ForEvidence,
    operations: tuple[CompilerOp, ...],
    indexes: dict[int, int],
) -> FpTail | None:
    index = indexes.get(end)
    if index is None or index < 3:
        return None
    load, fold, store = operations[index - 3 : index]
    expected = (
        ("fld64", "fold64", "fstp64")
        if template.wide
        else ("fld", "fold", "fstp")
    )
    if (load.kind, fold.kind, store.kind) != expected:
        return None
    if (
        load.args != (template.step,)
        or fold.args != ("+", template.variable)
        or store.args != (template.variable,)
    ):
        return None
    assignment = _assignment_ending(context.assignments, end)
    if assignment is not None and not _fp_increment(
        assignment.value,
        ("slot", "", template.variable),
        ("slot", "", template.step),
    ):
        return None
    support = combine_evidence(
        (load.offset, fold.offset, store.offset),
        () if assignment is None else assignment.evidence,
    )
    return FpTail(load.offset, support)


def _fp_header(goto: Fact, context: ForEvidence) -> FpHeader | None:
    jump = _goto_instruction(goto, context.instructions)
    commit = context.by_end.get(jump.offset) if jump is not None else None
    if jump is None or not _runtime_commit(commit):
        return None
    variable = _assignment_ending(context.assignments, commit.offset)
    step = _previous_assignment(variable, context.assignments)
    limit = _previous_assignment(step, context.assignments)
    if variable is None or step is None or limit is None:
        return None
    if any(_string_slot(item.value[0], context.facts) for item in (limit, step, variable)):
        return None
    return FpHeader(jump, limit, step, variable)


def _previous_assignment(
    assignment: Fact | None, assignments: tuple[Fact, ...]
) -> Fact | None:
    return (
        _assignment_ending(assignments, assignment.subject[0])
        if assignment is not None
        else None
    )


def _slot_address(value: object) -> int | None:
    if (
        isinstance(value, tuple)
        and len(value) >= 3
        and value[0] == "slot"
        and isinstance(value[2], int)
    ):
        return value[2]
    return None


def _string_slot(value: object, facts: frozenset[Fact]) -> bool:
    address = _slot_address(value)
    return any(
        fact.kind == "slot"
        and fact.subject == (address,)
        and fact.value[1] == ("string",)
        for fact in facts
    )


def _fp_increment(value: object, variable: object, step: object) -> bool:
    if not isinstance(value, tuple) or len(value) != 2:
        return False
    target, expression = value
    if not _same_slot(target, variable):
        return False
    return bool(
        isinstance(expression, tuple)
        and len(expression) == 4
        and expression[:2] == ("binary", "+")
        and any(_same_slot(operand, variable) for operand in expression[2:])
        and any(_same_slot(operand, step) for operand in expression[2:])
    )


def _same_slot(left: object, right: object) -> bool:
    left_address = _slot_address(left)
    return left_address is not None and left_address == _slot_address(right)


def _runtime_commit(instruction: Operation | None) -> bool:
    return bool(
        instruction is not None
        and instruction.kind == "tb.runtime"
        and instruction.operands == (0x87,)
    )


FP_FOR_FACT_PASSES: tuple[NamedPass, ...] = (("fp-for", fp_for_facts),)
