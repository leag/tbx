"""Source statement facts over signatures and semantic evidence."""

from __future__ import annotations

from collections.abc import Iterable

from tbd.facts import Evidence, NamedPass
from tbd.ir import Fact, Operation
from tbd.semantic import combine_evidence, resolve_expression

_DELAY_PARTS = {"DELAY_INIT", "DELAY_POLL"}


def statement_facts(
    evidence: Evidence, facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Expose complete source statements without consuming their evidence."""

    instructions = {
        instruction.offset: instruction for instruction in evidence.instructions
    }
    for signature in facts:
        statement = _simple_statement(signature, instructions)
        if statement is not None:
            yield statement
    yield from _static_dim_facts(evidence, facts)
    yield from _delay_facts(instructions, facts)


def _static_dim_facts(
    evidence: Evidence, facts: frozenset[Fact]
) -> Iterable[Fact]:
    if not evidence.instructions:
        return
    code_start = evidence.instructions[0].offset
    arrays = sorted(
        (fact for fact in facts if fact.kind == "layout.array"),
        key=lambda fact: fact.value[0],
    )
    for array in arrays:
        order, name, bounds, _kind, _base, _size, _count = array.value
        source_bounds = tuple(
            high if low == 0 else (low, high) for low, high in bounds
        )
        yield Fact(
            "semantic.dim",
            (code_start, order),
            (name, source_bounds, (), False),
            combine_evidence(array.evidence, (code_start,)),
            "anchored",
        )


def _simple_statement(
    signature: Fact, instructions: dict[int, Operation]
) -> Fact | None:
    if signature.kind != "signature" or not signature.subject:
        return None
    kind, operands = signature.value
    instruction = instructions.get(signature.subject[0])
    if kind != "tb.statement" or instruction is None:
        return None
    if not operands or operands[0] in _DELAY_PARTS:
        return None
    return Fact(
        "semantic.statement",
        (instruction.offset, instruction.end),
        operands,
        signature.evidence,
        "signature",
    )


def _delay_facts(
    instructions: dict[int, Operation], facts: frozenset[Fact]
) -> Iterable[Fact]:
    signatures = {
        fact.subject[0]: fact
        for fact in facts
        if fact.kind == "signature" and fact.subject
    }
    branches = {
        fact.subject[0]: fact
        for fact in facts
        if fact.kind == "flow.branch" and len(fact.subject) == 2
    }
    for value in facts:
        delay = _delay(value, instructions, signatures, branches, facts)
        if delay is not None:
            yield delay


def _delay(
    value: Fact,
    instructions: dict[int, Operation],
    signatures: dict[int, Fact],
    branches: dict[int, Fact],
    facts: frozenset[Fact],
) -> Fact | None:
    if value.kind != "expression.value" or not value.evidence:
        return None
    last = instructions.get(value.evidence[-1])
    begin = signatures.get(last.end) if last else None
    begin_instruction = _statement_instruction(begin, "DELAY_INIT", instructions)
    poll = signatures.get(begin_instruction.end) if begin_instruction else None
    poll_instruction = _statement_instruction(poll, "DELAY_POLL", instructions)
    commit = signatures.get(poll_instruction.end) if poll_instruction else None
    commit_instruction = _runtime_instruction(commit, 0x87, instructions)
    branch = branches.get(commit_instruction.end) if commit_instruction else None
    if branch is None or branch.value != ("<>", poll_instruction.offset):
        return None
    resolved = resolve_expression(value.value[0], facts)
    if resolved is None:
        return None
    support = combine_evidence(
        value.evidence,
        begin.evidence,
        poll.evidence,
        commit.evidence,
        branch.evidence,
        resolved.evidence,
    )
    return Fact(
        "semantic.delay",
        (value.evidence[0], branch.subject[1]),
        (resolved.value,),
        support,
        "anchored",
    )


def _statement_instruction(
    fact: Fact | None, name: str, instructions: dict[int, Operation]
) -> Operation | None:
    if fact is None or fact.value != ("tb.statement", (name, _delay_sub(name))):
        return None
    return instructions.get(fact.subject[0])


def _runtime_instruction(
    fact: Fact | None, vector: int, instructions: dict[int, Operation]
) -> Operation | None:
    if fact is None or fact.value != ("tb.runtime", (vector,)):
        return None
    return instructions.get(fact.subject[0])


def _delay_sub(name: str) -> int:
    return 0x28 if name == "DELAY_INIT" else 0x2A


STATEMENT_FACT_PASSES: tuple[NamedPass, ...] = (
    ("statements", statement_facts),
)
