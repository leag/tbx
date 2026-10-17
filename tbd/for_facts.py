from __future__ import annotations

import struct
from collections.abc import Iterable
from dataclasses import dataclass

from tbd.facts import Evidence, NamedPass, reads
from tbd.ir import Fact, Operation
from tbd.semantic import Resolved, combine_evidence, resolve_expression
from tbd.slots import VAR_BASE


@dataclass(frozen=True)
class IntegerForMatch:
    """Matched integer FOR-loop header and body boundaries."""

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
class ForEvidence:
    """Indexed operation and fact context for FOR-loop matching."""

    instructions: dict[int, Operation]
    by_end: dict[int, Operation]
    assignments: tuple[Fact, ...]
    branches: dict[tuple[object, ...], Fact]
    integer_slots: frozenset[object]
    facts: frozenset[Fact]


@dataclass(frozen=True)
class IntegerTest:
    """Decoded integer loop termination test."""

    start: int
    end: int
    variable_address: int
    limit: object
    limit_address: object | None
    evidence: tuple[int, ...]


@dataclass(frozen=True)
class ForSource:
    """Source expression and evidence for a FOR-loop variable."""

    header_start: int
    variable: object
    initial: object
    limit: object
    evidence: tuple[int, ...]


@reads(
    "constant",
    "expression.system",
    "expression.value",
    "flow.branch",
    "flow.goto",
    "layout.array",
    "semantic.assign",
    "slot",
    "tb.stack_check",
    "x86.into",
    "x86.jmp",
)
def integer_for_facts(evidence: Evidence, facts: frozenset[Fact]) -> Iterable[Fact]:
    """Recover integer FOR/NEXT loop facts."""

    context = _for_evidence(evidence.instructions, facts)
    for goto in (fact for fact in facts if fact.kind == "flow.goto"):
        match = _integer_for_match(goto, context)
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


def _for_evidence(
    instructions: tuple[Operation, ...], facts: frozenset[Fact]
) -> ForEvidence:
    return ForEvidence(
        {instruction.offset: instruction for instruction in instructions},
        {instruction.end: instruction for instruction in instructions},
        tuple(fact for fact in facts if _is_assignment(fact)),
        {fact.subject: fact for fact in facts if _is_branch(fact)},
        frozenset(
            address
            for fact in facts
            if (address := _integer_slot_address(fact)) is not None
        ),
        facts,
    )


def _is_assignment(fact: Fact) -> bool:
    return fact.kind == "semantic.assign" and len(fact.subject) == 2


def _is_branch(fact: Fact) -> bool:
    return fact.kind == "flow.branch" and len(fact.subject) == 2


def _integer_slot_address(fact: Fact) -> object | None:
    if (
        fact.kind != "slot"
        or len(fact.subject) != 1
        or len(fact.value) != 2
        or fact.value[1] != ("integer",)
    ):
        return None
    return fact.subject[0]


def _integer_for_match(
    goto: Fact,
    context: ForEvidence,
) -> IntegerForMatch | None:
    jump = _goto_instruction(goto, context.instructions)
    if jump is None:
        return None
    test = _integer_test(goto.value[0], context)
    if test is None:
        return None
    branch_instruction = context.instructions.get(test.end)
    branch = _branch_fact(branch_instruction, context.branches)
    increment = _previous_source_instruction(test.start, context.by_end)
    advanced = _integer_increment(increment)
    assignment = _assignment_ending(context.assignments, jump.offset)
    if branch is None or increment is None or advanced is None or assignment is None:
        return None
    # A local counted up to a local limit is incremented in the frame.
    if (
        isinstance(test.limit_address, tuple)
        and test.variable_address < VAR_BASE
        and bytes.fromhex(increment.raw)[:2] not in {b"\xff\x46", b"\xff\x4e"}
    ):
        return None
    source = _for_source(assignment, test, context.assignments)
    if source is None:
        return None
    increment_address, step = advanced
    if not _same_integer_variable(
        source.variable,
        test.variable_address,
        increment_address,
        context.integer_slots,
    ):
        return None
    body_start = jump.end
    if branch_instruction is None:
        return None
    loop_end = _loop_end(
        branch_instruction,
        branch,
        body_start,
        increment.offset,
        step,
        context.instructions,
    )
    if loop_end is None:
        return None
    support = combine_evidence(
        source.evidence,
        goto.evidence,
        (increment.offset,),
        test.evidence,
        branch.evidence,
    )
    return IntegerForMatch(
        source.header_start,
        jump.end,
        increment.offset,
        loop_end,
        source.variable,
        source.initial,
        source.limit,
        ("const", step),
        support,
    )


def _previous_source_instruction(
    end: int, by_end: dict[int, Operation]
) -> Operation | None:

    instruction = by_end.get(end)
    while instruction is not None and instruction.kind in {
        "x86.into",
        "tb.stack_check",
    }:
        instruction = by_end.get(instruction.offset)
    return instruction


def _for_source(
    assignment: Fact,
    test: IntegerTest,
    assignments: tuple[Fact, ...],
) -> ForSource | None:
    variable, initial = assignment.value
    # A local counts within its own procedure's frame.
    if (
        isinstance(test.limit_address, tuple)
        and isinstance(variable, tuple)
        and variable[:1] == ("proc-local",)
        and variable[:2] != test.limit_address[:2]
    ):
        return None
    if test.limit_address is None:
        return ForSource(
            assignment.subject[0],
            variable,
            initial,
            test.limit,
            assignment.evidence,
        )
    snapshot = _assignment_to_address_ending(
        assignments, test.limit_address, assignment.subject[0]
    )
    if snapshot is None:
        return None
    return ForSource(
        snapshot.subject[0],
        variable,
        initial,
        snapshot.value[1],
        combine_evidence(snapshot.evidence, assignment.evidence),
    )


def _assignment_ending(assignments: tuple[Fact, ...], end: int) -> Fact | None:
    matches = [fact for fact in assignments if fact.subject[1] == end]
    return matches[0] if len(matches) == 1 else None


def _assignment_to_address_ending(
    assignments: tuple[Fact, ...], address: object, end: int
) -> Fact | None:
    matches = [
        fact
        for fact in assignments
        if fact.subject[1] == end
        and isinstance(fact.value[0], tuple)
        and len(fact.value[0]) >= 3
        and (
            fact.value[0] == address
            or (fact.value[0][0] == "slot" and fact.value[0][2] == address)
        )
    ]
    return matches[0] if len(matches) == 1 else None


def _goto_instruction(
    goto: Fact, instructions: dict[int, Operation]
) -> Operation | None:
    if (
        goto.kind != "flow.goto"
        or len(goto.subject) != 2
        or len(goto.value) != 1
        or not isinstance(goto.value[0], int)
    ):
        return None
    instruction = instructions.get(goto.subject[0])
    if (
        instruction is None
        or instruction.kind != "x86.jmp"
        or instruction.end != goto.subject[1]
        or instruction.operands != goto.value
    ):
        return None
    return instruction


def _branch_fact(
    instruction: Operation | None,
    branches: dict[tuple[object, ...], Fact],
) -> Fact | None:
    if instruction is None:
        return None
    return branches.get((instruction.offset, instruction.end))


def _integer_test(target: int, context: ForEvidence) -> IntegerTest | None:
    instruction = context.instructions.get(target)
    immediate = _immediate_compare(instruction)
    if instruction is not None and immediate is not None:
        address, limit = immediate
        return IntegerTest(
            instruction.offset,
            instruction.end,
            address,
            ("const", limit),
            None,
            (instruction.offset,),
        )
    return _variable_compare(instruction, context)


def _variable_compare(
    load: Operation | None, context: ForEvidence
) -> IntegerTest | None:
    if load is None:
        return None
    load_raw = bytes.fromhex(load.raw)
    compare = context.instructions.get(load.end)
    compare_raw = b"" if compare is None else bytes.fromhex(compare.raw)
    if compare is None or len(load_raw) not in {3, 4} or len(compare_raw) not in {3, 4}:
        return None
    if load_raw[:2] == b"\x8b\x06" and compare_raw[:2] == b"\x39\x06":
        limit_address = struct.unpack_from("<H", load_raw, 2)[0]
        variable_address = struct.unpack_from("<H", compare_raw, 2)[0]
        limit_expression = ("memory", limit_address, "integer")
    elif (
        load_raw[:2] == b"\x8b\x46"
        and compare_raw[:2] == b"\x39\x06"
        and len(compare_raw) == 4
    ):
        # A variable of the program counted up to a SUB's local limit.
        local = _local_limit(load, load_raw[2], context.facts)
        if local is None:
            return None
        return IntegerTest(
            load.offset,
            compare.end,
            struct.unpack_from("<H", compare_raw, 2)[0],
            local.value,
            local.value,
            combine_evidence((load.offset, compare.offset), local.evidence),
        )
    elif load_raw[:2] == b"\x8b\x46" and compare_raw[:2] == b"\x39\x46":
        local = _local_limit(load, load_raw[2], context.facts)
        if local is not None:
            return IntegerTest(
                load.offset,
                compare.end,
                compare_raw[2],
                local.value,
                local.value,
                combine_evidence((load.offset, compare.offset), local.evidence),
            )
        limit_address = load_raw[2]
        variable_address = compare_raw[2]
        limit_expression = ("memory", limit_address, "integer")
    else:
        return None
    limit = resolve_expression(limit_expression, context.facts)
    if limit is None and load_raw[:2] == b"\x8b\x46":
        prior = [
            fact
            for fact in context.facts
            if fact.kind == "expression.value"
            and len(fact.subject) == 1
            and fact.subject[0] < load.offset
            and len(fact.value) == 1
            and isinstance(fact.value[0], tuple)
            and fact.value[0][0] == "proc-param"
        ]
        if len(prior) == 1:
            limit = Resolved(prior[0].value[0], prior[0].evidence)
            limit_address = None
    if limit is None:
        return None
    return IntegerTest(
        load.offset,
        compare.end,
        variable_address,
        limit.value,
        limit_address,
        combine_evidence((load.offset, compare.offset), limit.evidence),
    )


def _local_limit(
    load: Operation, displacement: int, facts: frozenset[Fact]
) -> Resolved | None:
    matches = [
        fact
        for fact in facts
        if fact.kind == "expression.value"
        and fact.subject == (load.offset,)
        and len(fact.value) == 1
        and isinstance(fact.value[0], tuple)
        and len(fact.value[0]) == 4
        and fact.value[0][0] == "proc-local"
        and fact.value[0][2:] == (displacement, "integer")
    ]
    if len(matches) != 1:
        return None
    return Resolved(matches[0].value[0], matches[0].evidence)


def _immediate_compare(instruction: Operation | None) -> tuple[int, int] | None:
    if instruction is None:
        return None
    raw = bytes.fromhex(instruction.raw)
    if len(raw) == 5 and raw[:2] == b"\x83\x3e":
        address = struct.unpack_from("<H", raw, 2)[0]
        return address, struct.unpack_from("<b", raw, 4)[0]
    if len(raw) == 6 and raw[:2] == b"\x81\x3e":
        return struct.unpack_from("<Hh", raw, 2)
    if len(raw) == 4 and raw[:2] == b"\x83\x7e":
        return raw[2], struct.unpack_from("<b", raw, 3)[0]
    return None


def _integer_increment(instruction: Operation | None) -> tuple[int, int] | None:
    if instruction is None:
        return None
    raw = bytes.fromhex(instruction.raw)
    if len(raw) == 3 and raw[:2] in {b"\xff\x46", b"\xff\x4e"}:
        return raw[2], 1 if raw[1] == 0x46 else -1
    if len(raw) == 4 and raw[:2] in {b"\xff\x06", b"\xff\x0e"}:
        address = struct.unpack_from("<H", raw, 2)[0]
        return address, 1 if raw[1] == 0x06 else -1
    if len(raw) == 5 and raw[:2] == b"\x83\x06":
        address = struct.unpack_from("<H", raw, 2)[0]
        return address, struct.unpack_from("<b", raw, 4)[0]
    if len(raw) == 6 and raw[:2] == b"\x81\x06":
        return struct.unpack_from("<Hh", raw, 2)
    return None


def _same_integer_variable(
    variable: object,
    compare_address: int,
    increment_address: int,
    integer_slots: frozenset[object],
) -> bool:
    return bool(
        isinstance(variable, tuple)
        and len(variable) >= 3
        and variable[0] in {"slot", "proc-local"}
        and variable[2] == compare_address == increment_address
        and (
            variable[2] in integer_slots
            or (
                variable[0] == "proc-local"
                and len(variable) >= 4
                and variable[3] == "integer"
            )
        )
    )


def _loop_end(
    branch_instruction: Operation,
    branch: Fact,
    body_start: int,
    increment_start: int,
    step: int,
    instructions: dict[int, Operation],
) -> int | None:
    if step == 0 or body_start > increment_start:
        return None
    wanted_condition = "<=" if step > 0 else ">="
    if branch.value == (wanted_condition, body_start):
        return branch_instruction.end
    exit_condition = ">" if step > 0 else "<"
    jump = instructions.get(branch_instruction.end)
    if (
        jump is None
        or jump.kind != "x86.jmp"
        or jump.operands != (body_start,)
        or branch.value != (exit_condition, jump.end)
    ):
        return None
    return jump.end


FOR_FACT_PASSES: tuple[NamedPass, ...] = (("integer-for", integer_for_facts),)
