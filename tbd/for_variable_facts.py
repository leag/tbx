from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from tbd.compiler_ops import CompilerOp, operation_indexes, translate_operations
from tbd.facts import Evidence, NamedPass, fact_key, reads
from tbd.for_facts import (
    ForEvidence,
    _assignment_ending,
    _assignment_to_address_ending,
    _for_evidence,
    _goto_instruction,
    _same_integer_variable,
)
from tbd.for_templates import VariableStepTemplate, match_variable_step_test
from tbd.ir import Fact
from tbd.operation_helpers import slot_address as _slot_address
from tbd.semantic import combine_evidence


@dataclass(frozen=True)
class VariableStepMatch:
    """Matched variable-step FOR-loop header."""

    header_start: int
    header_end: int
    next_start: int
    next_end: int
    variable: object
    initial: object
    limit: object
    step: object
    evidence: tuple[int, ...]


@dataclass(frozen=True)
class VariableStepUpdate:
    """Update expression and evidence for a variable-step loop."""

    start: int
    variable_address: int
    step_address: int
    evidence: tuple[int, ...]


@dataclass(frozen=True)
class HeaderSources:
    """Resolved initial, limit, and step expressions for a FOR header."""

    start: int
    limit: object
    step: object
    evidence: tuple[int, ...]


@reads(
    "expression.value",
    "flow.branch",
    "flow.goto",
    "semantic.assign",
    "semantic.sub_def",
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
def integer_variable_step_for_facts(
    evidence: Evidence, facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Recover integer FOR loops whose step is computed or variable."""

    yield from _byref_for_facts(evidence, facts)
    context = _for_evidence(evidence.instructions, facts)
    operations = translate_operations(evidence.instructions)
    indexes, by_address = operation_indexes(operations)
    for goto in (fact for fact in facts if fact.kind == "flow.goto"):
        match = _variable_step_match(goto, context, operations, indexes, by_address)
        if match is None:
            continue
        yield Fact(
            "semantic.for",
            (match.header_start, match.header_end),
            (match.variable, match.initial, match.limit, match.step),
            match.evidence,
            "anchored",
        )
        yield Fact(
            "semantic.next",
            (match.next_start, match.next_end),
            (match.variable,),
            match.evidence,
            "anchored",
        )


def _byref_for_facts(evidence: Evidence, facts: frozenset[Fact]) -> Iterable[Fact]:
    """Recognize an integer FOR whose variable is a BYREF parameter.

    The loop is the SUB's own: its initialization, increment and test all lie
    inside the SUB in that order, and the test branches back into the body
    between them.  Pieces with the same bytes elsewhere in the program belong
    to other statements.
    """
    instructions = evidence.instructions
    owners = sorted(
        (
            fact
            for fact in facts
            if fact.kind == "semantic.sub_def"
            and len(fact.subject) == 2
            and all(isinstance(bound, int) for bound in fact.subject)
            and len(fact.value) == 2
            and isinstance(fact.value[1], tuple)
            and fact.value[1]
        ),
        key=lambda fact: (fact.subject, fact_key(fact)),
    )
    values = [
        fact
        for fact in facts
        if fact.kind == "expression.value"
        and len(fact.value) == 1
        and isinstance(fact.subject[0], int)
    ]
    for owner in owners:
        entry = owner.value[0]
        low, high = owner.subject
        variable = _unique_parameter(values, entry, 10, low, high)
        limit = _unique_parameter(values, entry, 6, low, high)
        inside = [item for item in instructions if low <= item.offset < high]
        inits = [item for item in inside if item.raw == "26 c7 04 01 00"]
        increments = [item for item in inside if item.raw == "26 ff 04"]
        branches = [
            item
            for item in inside
            if item.raw.startswith("7e ")
            and item.operands
            and isinstance(item.operands[0], int)
        ]
        if (
            variable is None
            or limit is None
            or len(inits) != 1
            or len(increments) != 1
            or len(branches) != 1
        ):
            continue
        init, increment, branch = inits[0], increments[0], branches[0]
        body = branch.operands[0]
        if not (init.offset < body <= increment.offset < branch.offset):
            continue
        yield Fact(
            "semantic.for",
            (init.offset, body),
            (variable, ("const", 1), limit, ("const", 1)),
            (init.offset, branch.offset, increment.offset),
            "anchored",
        )
        yield Fact(
            "semantic.next",
            (increment.offset, increment.end),
            (variable,),
            (increment.offset, branch.offset),
            "anchored",
        )


def _unique_parameter(
    values: list[Fact], entry: object, offset: int, low: int, high: int
) -> object | None:
    """Return the integer parameter at ``offset`` read inside a SUB, if unique."""
    found = {
        fact.value[0]
        for fact in values
        if isinstance(fact.value[0], tuple)
        and fact.value[0][:2] == ("proc-param", entry)
        and len(fact.value[0]) == 4
        and fact.value[0][3] == "integer"
        and fact.value[0][2] == offset
        and low < fact.subject[0] < high
    }
    return next(iter(found)) if len(found) == 1 else None


def _variable_step_match(
    goto: Fact,
    context: ForEvidence,
    operations: tuple[CompilerOp, ...],
    indexes: dict[int, int],
    by_address: dict[int, CompilerOp],
) -> VariableStepMatch | None:
    jump = _goto_instruction(goto, context.instructions)
    preload_instruction = context.by_end.get(jump.offset) if jump is not None else None
    preload = (
        by_address.get(preload_instruction.offset)
        if preload_instruction is not None
        else None
    )
    step_address = _memory_load(preload)
    if jump is None or preload is None or step_address is None:
        return None
    assignment = _assignment_ending(context.assignments, preload.offset)
    update = _variable_step_update(goto.value[0], context, operations, indexes)
    if assignment is None or update is None or update.step_address != step_address:
        return None
    variable, initial = assignment.value
    variable_address = _slot_address(variable)
    if variable_address is None or not _same_integer_variable(
        variable,
        variable_address,
        update.variable_address,
        context.integer_slots,
    ):
        return None
    test_index = indexes.get(goto.value[0])
    template = (
        match_variable_step_test(
            operations,
            test_index,
            variable=variable_address,
            body=jump.end,
        )
        if test_index is not None
        else None
    )
    if template is None:
        return None
    sources = _header_sources(assignment, template, step_address, context.assignments)
    if sources is None:
        return None
    support = combine_evidence(
        sources.evidence,
        assignment.evidence,
        (preload.offset,),
        goto.evidence,
        update.evidence,
        template.evidence,
    )
    return VariableStepMatch(
        sources.start,
        jump.end,
        update.start,
        template.end,
        variable,
        initial,
        sources.limit,
        sources.step,
        support,
    )


def _variable_step_update(
    end: int,
    context: ForEvidence,
    operations: tuple[CompilerOp, ...],
    indexes: dict[int, int],
) -> VariableStepUpdate | None:
    assignment = _assignment_ending(context.assignments, end)
    index = indexes.get(assignment.subject[0]) if assignment is not None else None
    if assignment is None or index is None or index + 1 >= len(operations):
        return None
    load, add = operations[index : index + 2]
    step_address = _memory_load(load)
    variable_address = _memory_add(add)
    if step_address is None or variable_address is None or add.end != end:
        return None
    return VariableStepUpdate(
        load.offset,
        variable_address,
        step_address,
        combine_evidence(assignment.evidence, (load.offset, add.offset)),
    )


def _memory_load(operation: CompilerOp | None) -> int | None:
    return (
        operation.args[0]
        if operation is not None
        and operation.kind in {"movax_m", "movax_bp"}
        and isinstance(operation.args[0], int)
        else None
    )


def _memory_add(operation: CompilerOp | None) -> int | None:
    return (
        operation.args[0]
        if operation is not None
        and operation.kind in {"addm_ax", "addm_ax_bp"}
        and isinstance(operation.args[0], int)
        else None
    )


def _header_sources(
    assignment: Fact,
    template: VariableStepTemplate,
    step_address: int,
    assignments: tuple[Fact, ...],
) -> HeaderSources | None:
    needed = {step_address}
    if template.limit_kind == "cell":
        needed.add(template.limit)
    values: dict[int, object] = {}
    support = assignment.evidence
    start = assignment.subject[0]
    while needed:
        match = _previous_snapshot(assignments, needed, start)
        if match is None:
            return None
        address, snapshot = match
        values[address] = snapshot.value[1]
        support = combine_evidence(support, snapshot.evidence)
        start = snapshot.subject[0]
        needed.remove(address)
    limit = (
        ("const", template.limit)
        if template.limit_kind == "literal"
        else values[template.limit]
    )
    return HeaderSources(start, limit, values[step_address], support)


def _previous_snapshot(
    assignments: tuple[Fact, ...], needed: set[int], end: int
) -> tuple[int, Fact] | None:
    matches = [
        (address, snapshot)
        for address in needed
        if (snapshot := _assignment_to_address_ending(assignments, address, end))
        is not None
    ]
    return matches[0] if len(matches) == 1 else None


VARIABLE_FOR_FACT_PASSES: tuple[NamedPass, ...] = (
    ("integer-variable-step-for", integer_variable_step_for_facts),
)
