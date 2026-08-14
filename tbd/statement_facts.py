"""Source statement facts over signatures and semantic evidence."""

from __future__ import annotations

from collections.abc import Iterable

from tbd.facts import Evidence, NamedPass
from tbd.ir import Fact, Operation
from tbd.profile import EC_SOURCE_STATEMENTS
from tbd.semantic import combine_evidence, resolve_expression


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
    yield from _defseg_facts(instructions, facts)
    yield from _resume_facts(instructions, facts)
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
    if len(operands) < 2 or not isinstance(operands[1], int):
        return None
    if operands[1] == 0x26:
        return None
    source = EC_SOURCE_STATEMENTS.get(operands[1])
    if source is None:
        return None
    name, fixed_operands = source
    return Fact(
        "semantic.statement",
        (instruction.offset, instruction.end),
        (name, operands[1], *fixed_operands, *operands[2:]),
        signature.evidence,
        "signature",
    )


def _defseg_facts(
    instructions: dict[int, Operation], facts: frozenset[Fact]
) -> Iterable[Fact]:
    values = tuple(fact for fact in facts if fact.kind == "expression.value")
    for instruction in instructions.values():
        if instruction.kind == "tb.defseg_reset":
            yield Fact(
                "semantic.defseg",
                (instruction.offset, instruction.end),
                (),
                (instruction.offset,),
                "signature",
            )
            continue
        if instruction.kind == "tb.defseg_set" and instruction.operands:
            yield Fact(
                "semantic.defseg",
                (instruction.offset, instruction.end),
                (("const", instruction.operands[0]),),
                (instruction.offset,),
                "signature",
            )
            continue
        if not (
            instruction.kind == "tb.statement"
            and instruction.operands[:2] == ("DEF_SEG", 0x26)
        ):
            continue
        candidates = [
            value
            for value in values
            if value.evidence
            and (last := instructions.get(value.evidence[-1])) is not None
            and last.end == instruction.offset
        ]
        if len(candidates) != 1:
            continue
        resolved = resolve_expression(candidates[0].value[0], facts)
        if resolved is None:
            continue
        yield Fact(
            "semantic.defseg",
            (candidates[0].evidence[0], instruction.end),
            (resolved.value,),
            combine_evidence(
                candidates[0].evidence,
                (instruction.offset,),
                resolved.evidence,
            ),
            "signature",
        )


def _resume_facts(
    instructions: dict[int, Operation], facts: frozenset[Fact]
) -> Iterable[Fact]:
    signatures = {
        fact.subject[0]: fact
        for fact in facts
        if fact.kind == "signature" and fact.subject
    }
    for begin in signatures.values():
        if begin.value != ("tb.statement", ("RESUME_BEGIN", 0xBC)):
            continue
        begin_instruction = instructions.get(begin.subject[0])
        if begin_instruction is None:
            continue
        tail = instructions.get(begin_instruction.end)
        if tail is None:
            continue
        value = _resume_value(tail)
        if value is None:
            continue
        tail_signature = signatures.get(tail.offset)
        if tail.kind == "tb.statement" and tail_signature is None:
            continue
        yield Fact(
            "semantic.resume",
            (begin_instruction.offset, tail.end),
            value,
            combine_evidence(begin.evidence, (tail.offset,)),
            "signature",
        )


def _resume_value(tail: Operation) -> tuple[object, ...] | None:
    if tail.kind == "tb.statement" and tail.operands[:2] == (
        "RESUME_BARE", 0xBE
    ):
        return ()
    if tail.kind == "tb.statement" and tail.operands[:2] == (
        "RESUME_NEXT", 0xC0
    ):
        return ("NEXT",)
    if tail.kind in {"x86.jmp", "x86.jmp_far", "tb.run"} and tail.operands:
        target = tail.operands[0]
        return (target,) if isinstance(target, int) else None
    return None


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
